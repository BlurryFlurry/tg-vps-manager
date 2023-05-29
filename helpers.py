import json


# from main import logger
# from main import shell_exec

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


def format_bandwidth_usage(stats, usage_period, max_length=4096):
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
    current_message = []

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

                if current_length + len('\n'.join(message)) > max_length:
                    # Truncate the current message and add it to the list
                    messages.append('\n'.join(current_message))
                    # logger.debug(f'current_message)
                    current_message = []
                    current_length = 0

                current_message.append('\n'.join(message))
                current_length += len('\n'.join(message))
        if current_message:
            messages.append('\n'.join(current_message))
        return messages

    if usage_period.lower() == 'daily':
        message = ["Daily Bandwidth Usage",
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

                if current_length + len('\n'.join(message)) > max_length:
                    # Truncate the current message and add it to the list
                    messages.append('\n'.join(current_message))
                    # logger.debug(f'current_message)
                    current_message = []
                    current_length = 0

                current_message.append('\n'.join(message))
                current_length += len('\n'.join(message))
        if current_message:
            messages.append('\n'.join(current_message))
        return messages
