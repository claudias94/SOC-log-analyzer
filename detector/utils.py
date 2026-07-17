"""
utils.py

Shared utility functions used throughout the
Claus SOC Toolkit detection engine.
"""

from collections import Counter


def count_unique_ips(events):
    """
    Count unique IP addresses.

    Parameters
    ----------
    events : list

    Returns
    -------
    int
    """

    return len({event["ip"] for event in events})


def top_attacker(events):
    """
    Return the IP with the highest number
    of authentication attempts.

    Parameters
    ----------
    events : list

    Returns
    -------
    tuple

    (ip, attempts)
    """

    if not events:
        return None, 0

    counter = Counter(event["ip"] for event in events)

    return counter.most_common(1)[0]


def count_event_type(events, event_type):
    """
    Count a specific event type.

    Parameters
    ----------
    events : list

    event_type : str

    Returns
    -------
    int
    """

    return sum(
        1
        for event in events
        if event["type"] == event_type
    )


def filter_events(events, event_type):
    """
    Return only events of the specified type.
    """

    return [
        event
        for event in events
        if event["type"] == event_type
    ]


def summarize_events(events):
    """
    Generate a quick summary of event counts.

    Returns
    -------
    dict
    """

    summary = Counter()

    for event in events:
        summary[event["type"]] += 1

    return dict(summary)


def severity_order(level):
    """
    Numeric ordering for severity values.

    LOW < MEDIUM < HIGH < CRITICAL
    """

    order = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    return order.get(level.upper(), 0)


def highest_severity(alerts):
    """
    Determine the highest severity
    among a list of alerts.

    Parameters
    ----------
    alerts : list

    Returns
    -------
    str
    """

    if not alerts:
        return "LOW"

    highest = max(
        alerts,
        key=lambda alert: severity_order(
            alert["severity"]
        ),
    )

    return highest["severity"]
