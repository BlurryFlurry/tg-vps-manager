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
    :param usage_period: monthly, daily, hourly, etc. :param max_length: Maximum length of the output message. The
    output message will be truncated if it exceeds this length. :return:
    """
    try:
        data = json.loads(stats)
    except json.JSONDecodeError:
        return "Error: Failed to retrieve monthly bandwidth usage data."

    interfaces = data['interfaces']
    output = []
    if usage_period == 'Hourly':
        output.append("Hourly Bandwidth Usage")
        output.append("------------------------")

        for interface in interfaces:
            output.append(f"Interface: {interface['name']}")
            output.append("------------------------")

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

                output.append(f"Date: {year}-{month}-{day}")
                output.append(f"Time: {hour_number}:{minute_number}")
                output.append(f"Received: {sizeof_fmt(received)}")
                output.append(f"Sent: {sizeof_fmt(sent)}")
                output.append(f"Total: {sizeof_fmt(total)}")
                output.append("------------------------")

    if len(output) > max_length:
        output = output[:max_length]  # Trim the output to the maximum length
        output += "\n[...]\n"  # Add an ellipsis to indicate that the message is truncated

    messages = []
    while output:
        if len(output) <= max_length:
            messages.append(output)
            break
        else:
            # Find the last newline character within the maximum length
            last_newline_index = output[:max_length].rfind('\n')
            if last_newline_index == -1:
                # If no newline found, split at the maximum length
                last_newline_index = max_length
            messages.append(output[:last_newline_index].strip())
            output = output[last_newline_index:].strip()

    return messages
