#!/usr/bin/env python3
"""Statistics utilities for CICFlowMeter feature calculations.

All statistics are computed from stored raw values at flow termination,
not incrementally, to ensure mathematical exactness.

Uses the Python `statistics` module for mean/stdev/variance.
"""

import math
import statistics
from typing import List, Union

Numeric = Union[int, float]


def safe_mean(values: List[Numeric]) -> float:
    """Return mean of values, or 0 if empty."""
    if not values:
        return 0.0
    return statistics.mean(values)


def safe_stdev(values: List[Numeric]) -> float:
    """Return population-like standard deviation, or 0 if < 2 values.
    
    CICFlowMeter uses sample stdev (n-1 denominator) when there are >= 2 values.
    """
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def safe_variance(values: List[Numeric]) -> float:
    """Return sample variance, or 0 if < 2 values."""
    if len(values) < 2:
        return 0.0
    return statistics.variance(values)


def safe_min(values: List[Numeric]) -> Numeric:
    """Return min of values, or 0 if empty."""
    if not values:
        return 0
    return min(values)


def safe_max(values: List[Numeric]) -> Numeric:
    """Return max of values, or 0 if empty."""
    if not values:
        return 0
    return max(values)


def safe_sum(values: List[Numeric]) -> Numeric:
    """Return sum of values, or 0 if empty."""
    return sum(values)


def safe_div(numerator: Numeric, denominator: Numeric) -> float:
    """Return numerator/denominator, or 0 if denominator is 0."""
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)
