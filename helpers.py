import asyncio
import json
import logging
import random
import shutil
import string
from logging import Logger
from logging.handlers import RotatingFileHandler
from typing import Union
from events import Events
import aiohttp
import os

events = Events()

# <editor-fold desc="Logger configuration">
logger: Logger = logging.getLogger(__name__)

logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s] [%(name)s]  %(message)s")
logger.setLevel(logging.INFO)

fileHandler = RotatingFileHandler('/var/log/ptb.log', mode='a', maxBytes=5 * 1024 * 1024, backupCount=2, encoding=None)
fileHandler.setFormatter(logFormatter)
logger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
logger.addHandler(consoleHandler)
logging.getLogger("httpx").setLevel(logging.WARNING)


# </editor-fold>

def sizeof_fmt(num, suffix="B"):
    """
    convert bytes to human-readable format
    :param num:
    :param suffix:
    :return:
    """
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


async def get_bandwidth_data(period):
    if period == 'hourly':
        return await shell_exec_stdout(command='/usr/bin/vnstat --json h')
    elif period == 'daily':
        return await shell_exec_stdout(command='/usr/bin/vnstat --json d')
    elif period == 'monthly':
        return await shell_exec_stdout(command='/usr/bin/vnstat --json m')
    elif period == '5m':
        return await shell_exec_stdout(command='/usr/bin/vnstat -5 --json')
    elif period == 'top':
        return await shell_exec_stdout(command='/usr/bin/vnstat --top --json')


def format_bandwidth_usage(stats, usage_period, max_length=4084):
    """
    format bandwidth usage data into a list of strings that suitable for telegram bot message
    :param stats: bandwidth stats
    :param str usage_period: monthly, daily, hourly, etc.
    :param max_length: Maximum length of the output message. The output message will be truncated if it exceeds this length.
    :return: list
    """
    try:
        data = json.loads(stats)
    except json.JSONDecodeError:
        logger.exception("Error: Failed to retrieve monthly bandwidth usage data.", exc_info=True)
        return "Error: Failed to retrieve monthly bandwidth usage data."

    interfaces = data['interfaces']
    messages = []
    current_length = 0
    current_message = ""
    try:
        if usage_period.lower() == 'hourly':
            message = ["Hourly Bandwidth Usage",
                       "------------------------"]

            for interface in interfaces:
                message.append(f"Interface: {interface['name']}")
                message.append("------------------------")

                traffic = interface.get('traffic', {}).get('hour', [])

                for hour in traffic:
                    year = hour['date']['year']
                    month = hour['date']['month']
                    day = hour['date']['day']
                    hour_number = hour['time']['hour']
                    minute_number = hour['time']['minute']
                    received = hour['rx']
                    sent = hour['tx']
                    total = received + sent

                    message.append(f"Date: {year}-{month}-{day}")
                    message.append(f"Time: {hour_number}:{minute_number}")
                    message.append(f"Received: {sizeof_fmt(received)}")
                    message.append(f"Sent: {sizeof_fmt(sent)}")
                    message.append(f"Total: {sizeof_fmt(total)}")
                    message.append("------------------------")

                    if current_length + len('\n' + '\n'.join(message)) > max_length:
                        # Truncate the current message and add it to the list
                        messages.append(''.join(current_message))
                        current_message = ""
                        current_length = 0

                    current_message += '\n' + '\n'.join(message)
                    current_length += len(current_message)
                    message = []
            if current_message:
                messages.append(current_message)
            return messages

        if any([x == usage_period.lower() for x in ['daily', 'top']]):

            message = [f"{usage_period.title()} Bandwidth Usage",
                       "------------------------"]

            for interface in interfaces:
                message.append(f"Interface: {interface['name']}")
                message.append("------------------------")

                traffic = interface.get('traffic', {}).get('day', [])

                for day in traffic:
                    date = f"{day['date']['year']}-{day['date']['month']}-{day['date']['day']}"
                    received = day['rx']
                    sent = day['tx']
                    total = received + sent

                    message.append(f"Date: {date}")
                    message.append(f"Received: {sizeof_fmt(received)}")
                    message.append(f"Sent: {sizeof_fmt(sent)}")
                    message.append(f"Total: {sizeof_fmt(total)}")
                    message.append("------------------------")

                    if current_length + len('\n' + '\n'.join(message)) > max_length:
                        # Truncate the current message and add it to the list
                        messages.append(''.join(current_message))
                        current_message = ""
                        current_length = 0

                    current_message += '\n' + '\n'.join(message)
                    current_length += len(current_message)
                    message = []
                if current_message:
                    messages.append(current_message)
            return messages

        if usage_period.lower() == 'monthly':
            message = ["Monthly Bandwidth Usage",
                       "------------------------"]

            for interface in interfaces:
                message.append(f"Interface: {interface['name']}")
                message.append("------------------------")

                traffic = interface.get('traffic', {}).get('month', [])

                for month in traffic:
                    year = month['date']['year']
                    month_number = month['date']['month']
                    received = month['rx']
                    sent = month['tx']
                    total = received + sent

                    message.append(f"Month: {year}-{month_number}")
                    message.append(f"Received: {sizeof_fmt(received)}")
                    message.append(f"Sent: {sizeof_fmt(sent)}")
                    message.append(f"Total: {sizeof_fmt(total)}")
                    message.append("------------------------")

                    if current_length + len('\n' + '\n'.join(message)) > max_length:
                        # Truncate the current message and add it to the list
                        messages.append(''.join(current_message))
                        current_message = ""
                        current_length = 0

                    current_message += '\n' + '\n'.join(message)
                    current_length += len(current_message)
                    message = []
                if current_message:
                    messages.append(current_message)
            return messages

        if usage_period.lower() == '5m':
            message = ["Recent 5m Bandwidth Usage",
                       "------------------------"]

            for interface in interfaces:
                message.append(f"Interface: {interface['name']}")
                message.append("------------------------")

                traffic = interface.get('traffic', {}).get('fiveminute', [])

                for entry in traffic:
                    timestamp = entry["timestamp"]
                    rx = entry["rx"]
                    tx = entry["tx"]
                    time_str = f"{timestamp // 3600:02d}:{(timestamp % 3600) // 60:02d}"
                    bandwidth_str = f"RX: {sizeof_fmt(rx)} bytes, TX: {sizeof_fmt(tx)} bytes"
                    message.append(f"{time_str} - {bandwidth_str}")

                    if current_length + len('\n' + '\n'.join(message)) > max_length:
                        # Truncate the current message and add it to the list
                        messages.append(''.join(current_message))
                        current_message = ""
                        current_length = 0
                    current_message += '\n' + '\n'.join(message)
                    current_length += len(current_message)
                    message = []
                if current_message:
                    messages.append(current_message)
            return messages
    except Exception as e:
        logger.exception("Error formatting bandwidth usage", exc_info=True)
        logger.error(e)
        return


async def get_random_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    pw_template = ''.join(random.choice(characters) for i in range(8))
    return pw_template


async def get_local_version_tag():
    """
    return local installed repository version tag
    """
    home = os.path.expanduser('~')
    local_tag_file = os.path.join(home, '.config', 'ptb-service-version.txt')
    with open(local_tag_file, 'r') as f:
        return f.read().strip()


async def fetch_latest_version_tag():
    """
    :returns: latest version tag or none if not found
    :rtype string
    """
    repository_owner = 'BlurryFlurry'
    repository_name = 'tg-vps-manager'
    async with aiohttp.ClientSession() as session:
        url = f'https://api.github.com/repos/{repository_owner}/{repository_name}/tags'
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    tags = await response.json()
                    if tags:
                        return tags[0]['name']
                    else:
                        return None
                else:
                    logger.error("Error occurred while fetching tags.")
                    return None
        except Exception as e:
            logger.exception("Error occurred while fetching tags.", exc_info=True)
            return None


async def shell_exec(command, **kwargs):
    """
    execute shell command
    :param command: command to be executed
    :param kwargs:
    :return: process
    """
    logger.info('executing: %s', command)
    try:
        events.shell_exec_before(command)
        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE, **kwargs)
        stdout, stderr = await process.communicate()
        return_code = process.returncode
        logger.info('executed: %s \nstderr: %s \nstdout: %s \n', command, stderr.decode().strip(),
                    stdout.decode().strip())
        events.shell_exec_after(command)
        return return_code
    except Exception as e:
        logger.exception('Error executing: %s', command, exc_info=True)
        logger.error(e)
        return


async def shell_exec_stdout(command):
    logger.info('Executing command: %s', command)
    try:
        events.shell_exec_stdout_before(command)
        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        events.shell_exec_stdout_after(command)
        clean_stdout = stdout.decode().strip()
        logger.info('executed: %s \nstderr: %s \nstdout: %s \n', command, stderr.decode().strip(), clean_stdout)
        return clean_stdout
    except Exception as e:
        logger.exception('Error executing: %s', command, exc_info=True)
        logger.error(e)
        return


async def shell_exec_stdout_lines(command: str, oneline: bool = False) -> Union[list, str]:
    """

    :param command: command to execute
    :param oneline: True if oneline
    :return:
    """
    logger.info("Executing command: %s", command)
    try:
        events.shell_exec_stdout_lines_before(command)
        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
        if oneline:
            data = await process.stdout.readline()
            line = data.decode('ascii').strip()
            stderr = await process.stderr.read()
            await process.wait()
            logger.info('executed: %s \nstderr: %s \nstdout: %s \n', command, stderr.decode().strip(), line)
            return line

        stdout_bytes, stderr_bytes = await process.communicate()
        events.shell_exec_stdout_lines_after(command)
        stdout_decoded = [line.decode() for line in stdout_bytes.splitlines()]
        stderr_decoded = [line.decode() for line in stderr_bytes.splitlines()]
        logger.info('executed: %s \nstderr: %s \nstdout: %s \n', command, stderr_decoded, stdout_decoded)
        return stdout_decoded
    except Exception as e:
        logger.exception("Error executing: %s", command, exc_info=True)
        logger.error(e)
        return


async def change_banner(banner):
    logger.info('Setting new banner...')
    events.banner_change_before(banner)
    try:
        with open('/tmp/dropbear_banner.dat', 'r+') as f:
            f.write(banner)
        shutil.move('/tmp/dropbear_banner.dat', '/etc/dropbear/dropbear_banner.dat')
    except Exception as e:
        logger.exception("Error changing banner to:\n%s", banner, exc_info=True)
        logger.error(e)
        return False
    logger.info('Banner changed to:\n%s', banner)
    events.banner_change_after(banner)
    await shell_exec('/usr/bin/sudo /usr/bin/systemctl restart dropbear.service')
