#!/usr/bin/env python3
import asyncio
import logging
import sqlite3
from datetime import datetime
import html
from os import environ

conn = sqlite3.connect('tgbot.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS command_permissions
             (command_name TEXT, user_id INTEGER, can_access INTEGER, full_name TEXT, PRIMARY KEY (command_name, user_id))''')

conn.commit()

from telegram import Update
from telegram.ext import filters, MessageHandler, ApplicationBuilder, CommandHandler, ContextTypes, ConversationHandler

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)
log_file = '/var/log/ptb.log'

USERNAME, EXPIRE, MAX_LOGINS = range(3)
user = dict()


async def assert_can_run_command(command_name: str, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    c.execute('SELECT can_access FROM command_permissions WHERE user_id = ? AND command_name = ?',
              (user_id, command_name))
    result = c.fetchone()
    if result and result[0]:
        return True
    else:
        await context.bot.send_message(chat_id=user_id, text='You do not have permission to run this command.')
        return False


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('Hello, type /help for command details.')


async def help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('<b>Available commands:</b>\n\n'
                                    'type /create_user to create a user account.\n'
                                    'type /chpass to change a user password.\n'
                                    'type /reboot to restart the server\n\n' +
                                    '<a href="tg://user?id=5870625310">💠💠💠Coded by Ryan💠💠💠</a>'
                                    '', parse_mode='html')


async def cancel_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_message(chat_id=update.effective_chat.id, text="User creation canceled")
    return ConversationHandler.END


async def create_user():
    logger.info(f'creating user: {user}')
    if 'expire' in user:
        shell_command = f'/usr/bin/sudo /usr/sbin/useradd -M -s /usr/sbin/nologin -e $(date -d "+{user["expire"]} days" +%Y-%m-%d) "{user["username"]}"'
        await shell_exec(shell_command)
    else:
        shell_command = f'/usr/bin/sudo /usr/sbin/useradd -M -s /usr/sbin/nologin "{user["username"]}"'
        await shell_exec(shell_command)

    if 'max_logins' in user:
        shell_command = f'echo "{user["username"]} hard maxlogins {user["max_logins"]}" | sudo tee -a /etc/security/limits.conf'
        await shell_exec(shell_command)


async def change_password(user):
    logger.info(f'changing password for user: {user}')
    shell_command = f'/usr/bin/yes {user["password"]} | /usr/bin/sudo /usr/bin/passwd {user["username"]}'
    return await shell_exec(shell_command)


async def shell_exec(shell_command):
    logger.info('executing: ' + shell_command)
    shell = await asyncio.create_subprocess_shell(shell_command)
    return await shell.wait()


async def chpass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/chpass'
    if await assert_can_run_command(command_name, user_id, context):
        args = context.args
        if len(args) == 0:
            await context.bot.send_message(chat_id=update.effective_chat.id,
                                           text='Usage: /chpass username password')
            return
        user['username'] = context.args[0]
        user['password'] = context.args[1]
        if await shell_exec(f'/usr/bin/id {user["username"]}') == 0:
            await change_password(user)
            await update.message.reply_text('Password has been changed.')
        else:
            await update.message.reply_text('Invalid user')


async def user_create_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    command_name = '/create_user'

    if await assert_can_run_command(command_name, user_id, context):
        await update.message.reply_text('Enter the username you want to create')
        return USERNAME
    else:
        return ConversationHandler.END


async def user_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user['username'] = update.message.text
    logger.info(f'username sets to {user["username"]}')
    await update.message.reply_text(f'How many days do you want to keep the user: {user.get("username")}?')
    return EXPIRE


async def expire(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user['expire'] = update.message.text
    logger.info('user expire sets to {:>8} %s' % user['expire'])
    await update.message.reply_text('Enter the number of max login sessions for the user: %s' % user['username'])
    return MAX_LOGINS


async def skip_expire(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_expire = update.message.text
    logger.info('user expire sets to {:>8} %s' % user_expire)
    await update.message.reply_text('Enter the number of max login sessions for the user: %s' % user['username'])
    return MAX_LOGINS


async def user_max_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user['max_logins']: int = update.message.text
    logger.info('max login sets to {:>8} %s' % user['max_logins'])
    msg = await update.message.reply_text("Creating the user.. %s" % user['username'])
    await create_user()
    await msg.edit_text(text="The user %s has successfully created" % user['username'])
    return ConversationHandler.END


async def skip_max_logins(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user['max_logins']: int = 0
    await update.message.reply_text("max logins sets to unlimited)")
    logger.info('max login sets to {:>8} %s' % user['max_logins'])
    return ConversationHandler.END


async def reboot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    full_name = update.effective_user.full_name
    log_time = "{:%Y-%m-%d %H:%M:%S%z}".format(datetime.now())

    command_name = '/reboot'
    if await assert_can_run_command(command_name, user_id, context):
        await update.message.reply_text(text="rebooting...")
        await asyncio.create_subprocess_shell(
            f'echo {log_time}: {full_name} has performed the action: reboot >>{log_file}')
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
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, user_username)],
            EXPIRE: [MessageHandler(filters.Regex('^\d\d?$'), expire), CommandHandler('skip', skip_expire)],
            MAX_LOGINS: [MessageHandler(filters.Regex('^\d$'), user_max_logins),
                         CommandHandler('skip', skip_max_logins)]

        }, fallbacks=[CommandHandler('cancel', cancel_user)]
    )

    grant_handler = CommandHandler('grant', grant)
    reboot_handler = CommandHandler('reboot', reboot)
    help_handler = CommandHandler('help', help)
    user_password_handler = CommandHandler('chpass', chpass)

    application.add_handlers([
        user_create_conv_handler,
        grant_handler,
        help_handler,
        reboot_handler,
        user_password_handler,
        start_handler,
    ])

    application.run_polling()
