#!/usr/bin/env python3
import asyncio
import html
import logging

from helpers import logger, shell_exec, change_banner, shell_exec_stdout_lines, shell_exec_stdout, get_bandwidth_data
import re
import sqlite3
from os import environ
from helpers import get_random_password
from helpers import format_bandwidth_usage
from helpers import events, fetch_latest_version_tag, get_local_version_tag
from datetime import timedelta

conn = sqlite3.connect('tgbot.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS command_permissions
             (command_name TEXT, user_id INTEGER, can_access INTEGER, full_name TEXT, PRIMARY KEY (command_name, user_id))''')

conn.commit()

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import filters, MessageHandler, ApplicationBuilder, CommandHandler, ContextTypes, ConversationHandler, \
    CallbackQueryHandler

USERNAME, EXPIRE, MAX_LOGINS = range(3)
user = dict()
notified_updates = []


async def assert_can_run_command(command_name: str, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    c.execute('SELECT can_access FROM command_permissions WHERE user_id = ? AND command_name = ?',
              (user_id, command_name))
    result = c.fetchone()
    if result and result[0]:
        return True
    else:
        await context.bot.send_message(chat_id=user_id, text='You do not have permission to run this command.')
        await context.bot.send_message(chat_id=user_id,
                                       text='''This can happen for a variety of reasons. I am a part of the script named "Dig-my-tunnel" (github.comBlurryFlurry/dig-my-tunnel), which allows server owners to administer their servers using a simple telegram bot like me. \n If you know who owns the server that I manage, he must provide you access to perform the command. And if you don't know who that person is, I apologize; you may be conversing with a private bot controlled by someone. In this circumstance, I am unable to assist you.''')

        return False


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('Hello, type /help for command details.')


async def help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('<b>Available commands:</b>\n\n'
                                    '/create_user - create a user account.\n'
                                    '/chpass - change a user password.\n'
                                    '/deluser - delete a user.\n'
                                    '/lsusers - list users.\n'
                                    '/chbanner - update SSH banner\n\n' +
                                    '/server_stats - check server statistics\n' +
                                    '/vnstat - check bandwidth usage\n'
                                    '/vnstat_cfg - bandwidth monitor configuration\n\n'
                                    '/reboot - restart the server\n\n' +
                                    'Found a bug? Find your /release id and /logfile \n'
                                    'and forward it to <a href="tg://user?id=5870625310">me</a>.\n'
                                    'You can also report it to <a href="https://github.com/BlurryFlurry/dig-my-tunnel/issues">github</a>.\n\n'
                                    '<a href="tg://user?id=5870625310">💠💠💠Coded by Ryan💠💠💠</a>'
                                    '', parse_mode='html', disable_web_page_preview=True)


async def cancel_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_message(chat_id=update.effective_chat.id, text="User creation canceled")
    return ConversationHandler.END


async def create_user():
    logger.info(f'creating user: {user}')
    events.create_user_before(user)
    if 'expire' in user:
        shell_command = f'/usr/bin/sudo /usr/sbin/useradd -M -s /usr/sbin/nologin -e $(/usr/bin/date -d "+{user["expire"]} days" +%Y-%m-%d) "{user["username"]}"'
        await shell_exec(shell_command)
    else:
        shell_command = f'/usr/bin/sudo /usr/sbin/useradd -M -s /usr/sbin/nologin "{user["username"]}"'
        await shell_exec(shell_command)

    if 'max_logins' in user and user['max_logins'] != 0:
        await shell_exec('/usr/bin/mkdir -p /etc/security/limits.d')
        shell_command = f'echo "{user["username"]} hard maxlogins {user["max_logins"]}" | /usr/bin/sudo tee -a /etc/security/limits.d/{user["username"]}.conf'
        await shell_exec(shell_command)
    events.create_user_after(user)


async def get_users_list():
    process = await asyncio.create_subprocess_shell(
        r"/usr/bin/sudo /usr/bin/getent shadow | /usr/bin/grep '^[^:]*:[^\*!]' | /usr/bin/cut -d ':' -f 1",
        stdout=asyncio.subprocess.PIPE)
    output_bytes, _ = await process.communicate()

    users = [line.decode() for line in output_bytes.splitlines()]
    return users


async def assert_deletable_user(user):
    return True if user['username'] in await get_users_list() else False


async def user_delete(user):
    if await user_exist(user):
        # delete file if exist
        await shell_exec(f'/usr/bin/sudo /usr/bin/rm -rf /etc/security/limits.d/{user["username"]}.conf')
        await shell_exec(f'/usr/bin/sudo /usr/sbin/userdel -rf {user["username"]}')
    else:
        return False


async def deluser(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/deluser'
    if await assert_can_run_command(command_name, user_id, context):
        args = context.args
        if len(args) == 0:
            await context.bot.send_message(chat_id=update.effective_chat.id,
                                           text='Usage: /deluser username')
            return
        user['username'] = context.args[0]
        if await assert_deletable_user(user):
            await user_delete(user)
            await update.message.reply_text('User has been deleted.')
        else:
            await update.message.reply_text('Invalid user')


async def user_exist(user):
    return True if await shell_exec(f'/usr/bin/id {user["username"]}') == 0 else False


async def change_password(user):
    logger.info(f'changing password for user: {user}')
    shell_command = '/usr/bin/sudo /usr/bin/passwd %s' % user["username"]
    process = await asyncio.create_subprocess_shell(shell_command, stdin=asyncio.subprocess.PIPE)
    inp = user['password'] + "\n" + user['password'] + "\n"
    inp = inp.encode()
    _ = await process.communicate(input=inp)


async def lsusers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/lsusers'
    if await assert_can_run_command(command_name, user_id, context):
        users = await get_users_list()
        if not users:
            await update.message.reply_text('No users to display. \n'
                                            'If you have created password less user, try setting the password with '
                                            '/chpass command')
            return
        msg = str()
        for user in users:
            msg += '<code>' + html.escape(user) + '</code>\n'
        logger.info(msg)
        await update.message.reply_text(msg, parse_mode='HTML')


async def get_user_expiry_date(username):
    command = f'''/usr/bin/sudo /usr/bin/chage -l {username} | /usr/bin/grep "Account expires" | /usr/bin/cut -d ':' -f 2'''
    logger.info(command)
    process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE)
    data = await process.stdout.read()
    expiry = data.decode('ascii').strip()
    await process.wait()

    return expiry


async def get_user_create_date(username):
    command = '/usr/bin/sudo /usr/bin/passwd -S ' + username + " | /usr/bin/awk '{print $3}'"
    logger.info(command)
    process = await asyncio.create_subprocess_shell(command,
                                                    stdout=asyncio.subprocess.PIPE)
    data = await process.stdout.readline()
    creation_date = data.decode('ascii').rstrip()
    await process.wait()
    return creation_date


async def get_public_ip():
    command = '/usr/bin/wget -qO- ifconfig.me | /usr/bin/xargs /usr/bin/echo'
    process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE)
    stdout, _ = await process.communicate()
    return stdout.decode('ascii').strip()


async def chpass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/chpass'
    if await assert_can_run_command(command_name, user_id, context):
        args = context.args
        if len(args) != 2:
            await context.bot.send_message(chat_id=update.effective_chat.id,
                                           text='Usage: /chpass username password')
            return
        user['username'] = context.args[0]
        user['password'] = context.args[1]
        if await user_exist(user):
            await change_password(user)
            await update.message.reply_text('Password has been changed.')

            created_time = await get_user_create_date(user['username'])
            expiry_date = await get_user_expiry_date(user['username'])
            hostname = await get_public_ip()
            logger.info('created: %s', str(created_time))
            logger.info('expiry: %s', str(expiry_date))

            await context.bot.send_message(text=f'''
<pre>
―――⋞ New SSH account settings ⋟―――
☰☰☰☰☰☰✦✦✦✦✦✦☰☰☰☰☰☰☰

⁅≔――――――――――――≍―――――――――――――≔⁆
➬ Host:    ❋ ➫ {hostname}
⁅≔――――――――――――≍―――――――――――――≔⁆
➬ Username ❋ ➫ {user['username']}
➬ Password ❋ ➫ {user['password']}
⁅≔――――――――――――≍―――――――――――――≔⁆
➬ Expiry   ❋ ➫ {expiry_date}
➬ Created  ❋ ➫ {created_time}
⁅≔――――――――――――≍―――――――――――――≔⁆
 Port      ❋ ➫ 22 / 443
 Badvpn    ❋ ➫ 7300
⁅≔――――――――――――≍―――――――――――――≔⁆
</pre>
                                                            <a href="https://github.com/BlurryFlurry/dig-my-tunnel">❬../❭</a> ''',
                                           chat_id=user_id, parse_mode='HTML', disable_web_page_preview=True)
        else:
            await update.message.reply_text('Invalid user')


async def chbanner_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('Maybe next time...')
    return ConversationHandler.END


async def chbanner_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/chbanner'

    if await assert_can_run_command(command_name, user_id, context):
        await update.message.reply_text('Paste the SSH banner HTML code and send (or /cancel)')
        return 1
    else:
        return ConversationHandler.END


async def chbanner(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = await update.message.reply_text('Updating banner..')
    banner = update.message.text
    logger.info('changing SSH banner:\n%s', banner)
    success_state = await change_banner(banner)
    if not success_state:
        await msg.edit_text('Failed to update banner.')
        return ConversationHandler.END
    await msg.edit_text('SSH banner has been successfully updated.')
    return ConversationHandler.END


async def user_create_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/create_user'

    if await assert_can_run_command(command_name, user_id, context):
        await update.message.reply_text('Enter the username you want to create [or /cancel]')
        return USERNAME
    else:
        return ConversationHandler.END


async def user_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user['username'] = update.message.text
    if await user_exist(user):
        await update.message.reply_text("User already exists, pick a different username [or /cancel]")
        return USERNAME
    elif not re.match(r'^[a-z_][a-z0-9_-]{0,31}$', user['username']):
        await update.message.reply_text("Invalid username, pick a different username [or /cancel]")
        return USERNAME
    logger.info(f'username sets to {user["username"]}')
    await update.message.reply_text(
        f'How many days do you want to keep the user: {user.get("username")}?' + ' [or /skip /cancel]')
    return EXPIRE


async def expire(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user['expire'] = update.message.text
    logger.info('user expire sets to {:>8} %s' % user['expire'])
    await update.message.reply_text(
        'Enter the number of max login sessions for the user: %s' % user['username'] + ' [or /skip /cancel]')
    return MAX_LOGINS


async def release(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id == int(environ.get('grant_perm_id')):  # shows debug info only to the admin
        with open('release-id.txt', 'r') as f:
            release_id = f.read()
        await update.message.reply_text(release_id)

    else:
        await context.bot.send_message(chat_id=update.effective_chat.id,
                                       text='Sorry, you do not have permission to use this command.')


async def logfile(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id == int(environ.get('grant_perm_id')):  # shows debug info only to the admin
        args = context.args
        if len(args) == 0:
            with open('/var/log/ptb.log', 'rb') as f:
                await update.message.chat.send_document(f)
        else:
            if args[0].lower() == 'clear':
                open('/var/log/ptb.log', 'w+').close()
                await update.message.reply_text('Log file cleared')
            elif args[0].lower() == 'debug':
                logger.setLevel(logging.DEBUG)
                await update.message.reply_text('Logging: debug mode enabled')
            elif args[0].lower() == 'info':
                await update.message.reply_text('Logging: info mode enabled')
                logger.setLevel(logging.INFO)

    else:
        await context.bot.send_message(chat_id=update.effective_chat.id,
                                       text='Sorry, you do not have permission to use this command.')


async def skip_expire(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_expire = update.message.text
    logger.info('user expire sets to {:>8} %s' % user_expire)
    await update.message.reply_text(
        'Enter the number of max login sessions for the user: %s' % user['username'] + ' [or /skip /cancel]')
    return MAX_LOGINS


async def user_max_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user['max_logins']: int = update.message.text
    logger.info('max login sets to {:>8} %s' % user['max_logins'])
    msg = await update.message.reply_text("Creating the user.. %s" % user['username'])
    await create_user()
    pw_template = await get_random_password()
    await msg.edit_text(
        text=f"The user <code>{user['username']}</code> has successfully created. set the password using <code>/chpass {user['username']} {pw_template}</code>",
        parse_mode='HTML')
    return ConversationHandler.END


async def skip_max_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user['max_logins']: int = 0
    logger.info('max login sets to {:>8} %s' % user['max_logins'])
    msg = await update.message.reply_text("Creating the user.. %s" % user['username'])
    await create_user()

    # get random password pf length 8 with letters, digits, and symbols
    pw_template = await get_random_password()
    await msg.edit_text(
        text=f"The user <code>{user['username']}</code> has successfully created. set the password using <code>/chpass {user['username']} {pw_template}</code>",
        parse_mode='HTML')
    return ConversationHandler.END


async def get_service_processes():
    processes = await shell_exec_stdout_lines(
        """/usr/bin/sudo /usr/bin/ss -ntlp | /usr/bin/awk '!/Peer/ {split($4, a, ":"); sub("users:", "", $6); gsub(",", " | ", $6); gsub("\\)\\)", "", $6); gsub("\\\(\\\(", "", $6); print "Port:" a[length(a)] " | " $6 }'""")
    return processes


async def server_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    command_name = '/server_stats'
    if await assert_can_run_command(command_name, user_id, context):
        service_processes_list = await get_service_processes()
        service_processes = str()
        for line in service_processes_list:
            service_processes += html.escape(line) + '\n'
        server_load = await shell_exec_stdout_lines("/usr/bin/uptime | /usr/bin//awk -F: '{ print $5 }'", True)
        uptime = await shell_exec_stdout_lines('/usr/bin/uptime --pretty', True)
        server_ip = await get_public_ip()
        await context.bot.send_message(text=f'''
        <pre>
―――⋞ Server statistics ⋟―――

⁅≔――――――――――――≍―――――――――――――≔⁆
➬ Server IP   ❋ ➫ {server_ip}
➬ Server Load ❋ ➫ {server_load}
➬ {uptime}
⁅≔――――――――――――≍―――――――――――――≔⁆
            Ports      
 Dropbear   ❋ ➫ 22
 SSH        ❋ ➫ 22
 Badvpn     ❋ ➫ 7300
⁅≔――――――――――――≍―――――――――――――≔⁆
        Service processes

{service_processes}
⁅≔――――――――――――≍―――――――――――――≔⁆

</pre>
                                                                    <a href="https://github.com/BlurryFlurry/dig-my-tunnel">❬../❭</a> ''',
                                       chat_id=user_id, parse_mode='HTML', disable_web_page_preview=True)


# function to get hourly bandwidth usage


async def get_available_interfaces():
    """function to get available interfaces"""
    command = '/usr/bin/vnstat --iflist'
    output = await shell_exec_stdout_lines(command, True)
    # Parse the output to extract interface names
    if output.startswith("Available interfaces:"):
        interfaces = output.split(":")[1].strip().split()
        return interfaces
    return []


async def vnstat_cfg(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/vnstat_cfg'
    if await assert_can_run_command(command_name, user_id, context):
        interfaces = await get_available_interfaces()
        keyboard = [[InlineKeyboardButton(interface, callback_data=interface)] for interface in interfaces]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text('Select a network interface:', reply_markup=reply_markup)
        return


# function to handle callback query vnstat_save
async def vnstat_add_interface(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/vnstat_cfg'
    if await assert_can_run_command(command_name, user_id, context):
        query = update.callback_query
        await query.answer()
        interface = query.data
        await query.edit_message_text(text=f'Adding interface: {interface}')
        command = f'/usr/bin/vnstat --add -i {interface}'
        await shell_exec(command)
        await query.edit_message_text(text=f'Interface: {interface} added')
        return


async def vnstat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Show bandwidth usage report
    :param update:
    :param context:
    :return:
    """
    user_id = update.effective_user.id
    command_name = '/vnstat'
    if await assert_can_run_command(command_name, user_id, context):
        args = context.args
        if not len(args) == 1:
            await context.bot.send_message(chat_id=update.effective_chat.id,
                                           text='Usage: /vnstat arg [daily | monthly | hourly | top | 5m ]')
            return
        if any([x == args[0].lower() for x in ['hourly', 'daily', 'monthly', 'top', '5m']]):
            bandwidth_usage = await get_bandwidth_data(args[0].lower())
            formatted_output_messages = format_bandwidth_usage(bandwidth_usage, args[0].lower())
            for formatted_output_message in formatted_output_messages:
                await update.message.reply_text('<pre>' + formatted_output_message + '</pre>',
                                                parse_mode='html')
        else:
            await context.bot.send_message(chat_id=update.effective_chat.id,
                                           text='Usage: /vnstat arg [daily | monthly | hourly | top | 5m ]')


async def force_check_for_updates(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/force_check_for_updates'
    if await assert_can_run_command(command_name, user_id, context):
        await update.message.reply_text(text="Checking for updates...")
        logger.info(f'User {user_id} has performed the action: check_for_updates ')
        await check_for_updates(context,  force=True)


async def check_for_updates(context: ContextTypes.DEFAULT_TYPE, force=False):
    chat_id = int(environ.get('grant_perm_id'))
    logger.debug('Sending heart beat to the upstream')
    latest_tag = await fetch_latest_version_tag()
    local_tag = await get_local_version_tag()
    logger.debug('latest version tag: %s,  local version tag: %s', latest_tag, local_tag)
    if local_tag != latest_tag and latest_tag not in notified_updates:
        logger.info('Sending update notification')
        await context.bot.send_message(chat_id=chat_id,
                                       text=f'New version available: {latest_tag}')
        logger.info('update notification sent')
        notified_updates.append(latest_tag)
    else:
        if force:
            await context.bot.send_message(chat_id=chat_id, text='No updates available.')


async def reboot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    full_name = update.effective_user.full_name

    command_name = '/reboot'
    if await assert_can_run_command(command_name, user_id, context):
        await update.message.reply_text(text="rebooting...")
        logger.info(f'{full_name} has performed the action: reboot ')

        await asyncio.create_subprocess_shell('/usr/bin/sudo /usr/sbin/reboot')


async def grant(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id == int(environ.get('grant_perm_id')):  # Replace with the user ID that has permission to grant access
        args = context.args
        full_name = update.effective_user.full_name
        if len(args) == 0:
            await context.bot.send_message(chat_id=update.effective_chat.id,
                                           text='Usage: /grant command_name user_id 1 [command_name user_id 1 ...]')
            return
        for i in range(0, len(args), 3):
            command_name = args[i]
            target_id = int(args[i + 1])
            can_access = int(args[i + 2])
            if not command_name[0] == "/":
                await update.message.reply_text('Invalid command')
                return False
            c.execute(
                'INSERT OR REPLACE INTO command_permissions (command_name, user_id, can_access, full_name) VALUES (?, ?, ?, ?)',
                (command_name, target_id, can_access, full_name))
        conn.commit()
        await context.bot.send_message(chat_id=update.effective_chat.id, text='Permissions updated.')
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id,
                                       text='Sorry, you do not have permission to use this command.')


if __name__ == '__main__':
    application = ApplicationBuilder().token(environ.get('telegram_bot_token')).build()

    start_handler = CommandHandler('start', start)

    user_create_conv_handler = ConversationHandler(
        entry_points=[CommandHandler('create_user', user_create_start)], states={
            USERNAME: [MessageHandler(
                filters.TEXT & filters.Regex(r'^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$') & ~filters.COMMAND,
                user_username)],
            EXPIRE: [MessageHandler(filters.Regex('^\d\d?$'), expire), CommandHandler('skip', skip_expire)],
            MAX_LOGINS: [MessageHandler(filters.Regex('^\d$'), user_max_logins),
                         CommandHandler('skip', skip_max_logins)]

        }, fallbacks=[CommandHandler('cancel', cancel_user)]
    )

    chbanner_conv_handler = ConversationHandler(
        entry_points=[CommandHandler('chbanner', chbanner_start)], states={
            1: [MessageHandler(
                filters.TEXT & ~filters.COMMAND,
                chbanner)]

        }, fallbacks=[CommandHandler('cancel', chbanner_cancel)]
    )
    vnstat_cfg_handler = CommandHandler('vnstat_cfg', vnstat_cfg)
    vnstat_cfg_add_interface_handler = CallbackQueryHandler(vnstat_add_interface)

    grant_handler = CommandHandler('grant', grant)
    logfile_handler = CommandHandler('logfile', logfile)
    release_handler = CommandHandler('release', release)
    lsusers_handler = CommandHandler('lsusers', lsusers)
    reboot_handler = CommandHandler('reboot', reboot)
    help_handler = CommandHandler('help', help)
    user_password_handler = CommandHandler('chpass', chpass)
    deluser_handler = CommandHandler('deluser', deluser)
    server_stats_handler = CommandHandler('server_stats', server_stats)
    vnstat_handler = CommandHandler('vnstat', vnstat)
    updatecheck_handler = CommandHandler('force_check_for_updates', force_check_for_updates)

    application.add_handlers([
        user_create_conv_handler,
        chbanner_conv_handler,
        vnstat_cfg_handler,
        vnstat_cfg_add_interface_handler,
        server_stats_handler,
        updatecheck_handler,
        logfile_handler,
        release_handler,
        vnstat_handler,
        lsusers_handler,
        deluser_handler,
        grant_handler,
        help_handler,
        reboot_handler,
        user_password_handler,
        start_handler,
    ])

    application.job_queue.run_repeating(check_for_updates, interval=timedelta(minutes=15), first=0)
    application.run_polling()
