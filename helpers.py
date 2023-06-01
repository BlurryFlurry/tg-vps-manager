import asyncio
import json
import logging
import random
import string
from logging import Logger
from typing import Union

# <editor-fold desc="Logger configuration">
logger: Logger = logging.getLogger(__name__)

logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s] [%(name)s]  %(message)s")
logger.setLevel(logging.INFO)

fileHandler = logging.FileHandler('/var/log/ptb.log')
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
        return "Error: Failed to retrieve monthly bandwidth usage data."

    interfaces = data['interfaces']
    messages = []
    current_length = 0
    current_message = ""

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

    if any([x in usage_period.lower() for x in ['daily', 'top']]):

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


async def get_random_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    pw_template = ''.join(random.choice(characters) for i in range(8))
    return pw_template


async def shell_exec(shell_command, **kwargs):
    """
    execute shell command
    :param shell_command: command to be executed
    :param kwargs:
    :return: process
    """
    logger.info('executing: %s', shell_command)
    process = await asyncio.create_subprocess_shell(shell_command, **kwargs)
    return await process.wait()


async def shell_exec_stdout(command: str, oneline: bool = False) -> Union[list, str]:
    """

    :param command: command to execute
    :param oneline: True if oneline
    :return:
    """
    logger.info("Running: %s", command)

    process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE)

    if oneline:
        data = await process.stdout.readline()
        line = data.decode('ascii').strip()
        await process.wait()
        return line

    output_bytes, _ = await process.communicate()

    lines_decoded = [line.decode() for line in output_bytes.splitlines()]
    return lines_decoded


async def change_banner(banner):
    with open('/etc/dropbear/banner.dat', 'w') as f:
        f.write(banner)
    await shell_exec('/usr/bin/sudo /usr/bin/systemctl restart dropbear.service')
