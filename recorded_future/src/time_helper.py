import re
from datetime import datetime, timedelta

VALID_TIME_REGEX = r'^([1-9]?[0-9]+[dDhH])$'
TIMEFORMAT = '%Y-%m-%dT%H:%M:%SZ'


def rel_time_to_date(relative_time, start_time):
    """Convert a relative time to a date. Minutes not supported.

    Example:
            1h -> Return +1h from start_time
            1d -> Return +1d from start_time.

    Args:
        relative_time (str): 7d, 3h, etc..


    Raises:
        ValueError: if the relative time is invalid

    Returns:
        str: time delta, for example: ``2022-08-08T13:11``
    """
    match = re.match(VALID_TIME_REGEX, relative_time)
    if match is None:
        raise ValueError(
            f"Invalid relative time '{relative_time}'. Accepted format: [integer][h|d]",
        )
    relative_time = match.groups()[-1]
    start_time = datetime.strptime(start_time, TIMEFORMAT)
    digit = int(re.findall(r'^\d+', relative_time)[0])
    if relative_time.endswith('d'):
        return (start_time + timedelta(days=digit)).strftime(TIMEFORMAT)

    return (start_time + timedelta(hours=digit)).strftime(TIMEFORMAT)
