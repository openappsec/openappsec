# Scoring Mechanisms Summary

This document summarizes the calculation methods for User Reputation scores and Payload/URL/Parameter confidence scores within the WAAP system.

## User Reputation Score

-   **Relevant Files:**
    -   `components/security_apps/waap/waap_clib/BehaviorAnalysis.cc`
    -   `components/security_apps/waap/waap_clib/BehaviorAnalysis.h`

-   **Key Function for Final Score Calculation:**
    -   `BehaviorAnalyzer::getRelativeReputation(double absoluteReputation)`

-   **Key Data Structure Holding the Score:**
    -   `ReputationData`: The final score is stored in its `relativeReputation` field (a `double`).

-   **Brief Overview of Calculation Flow:**
    1.  **Traffic Logging & Initial Scoring:**
        -   Incoming requests are processed by `BehaviorAnalyzer::analyze_behavior()`.
        -   If an attack is detected (based on keyword matches and scores from other components), `TopBucket::putAttack()` is called. This updates `attacksScoreSum` and `missed_urls` in `Counters` for the source IP, User-Agent (UA), and IP+UA combination within the respective `Source` objects.
        -   For legitimate traffic, `TopBucket::addKeys()` is called, incrementing `countLegit` in the `Counters` for the IP, UA, and IP+UA.
    2.  **Individual Source Reputation (`Source::getInfo()`):**
        -   For each source type (IP, UA, IP+UA), this function calculates a `reputation` score.
        -   This calculation involves:
            -   `missed_urls_score`: Derived from `Counters::missed_urls`.
            -   `legit_vs_attacks`: A score comparing `Counters::countLegit` to `Counters::attacksScoreSum`.
            -   `coverage`: A metric based on `missed_urls_score`.
        -   The final `reputation` for the source is a normalized product of these components.
    3.  **Absolute Reputation (`TopBucket::getInfo()`):**
        -   This function calls `Source::getInfo()` for IP, UA, and IP+UA.
        -   The `absoluteReputation` is calculated as the simple average of these three individual reputation scores.
    4.  **Global Statistics Update (`BehaviorAnalyzer::updateAvrageAndVariance()`):**
        -   The newly calculated `absoluteReputation` is used to incrementally update the global mean (`m_reputation_mean`) and variance (`m_variance`) of all absolute reputation scores observed by the system.
    5.  **Relative Reputation - Final Score (`BehaviorAnalyzer::getRelativeReputation()`):**
        -   This function takes the `absoluteReputation`.
        -   It normalizes this score by comparing it to the global `m_reputation_mean`, adjusted by the global `m_variance` (which is itself modified by a `viscosity` factor to slow down rapid changes).
        -   The normalized deviation is then passed through `BehaviorAnalyzer::errorProbabilityScore()`, which uses the mathematical error function (`erf`) to produce a probabilistic score (0.0 to 1.0).
        -   This probabilistic score is then scaled by 10 to yield the final `relativeReputation`, which typically ranges from 0.0 to 10.0. This `relativeReputation` is the User Reputation Score.

## Payload, URL, and Parameter Confidence Scores

-   **Relevant Files:**
    -   `components/security_apps/waap/waap_clib/ConfidenceCalculator.cc`
    -   `components/security_apps/waap/waap_clib/ConfidenceCalculator.h`

-   **Key Function for Score Updates:**
    -   `ConfidenceCalculator::calculateInterval()`

-   **Key Data Structure for Accumulating Scores:**
    -   `m_confidence_level` (`UMap<Key, UMap<Val, double>>`): A map where `Key` identifies the item being scored (e.g., "param#username") and `Val` is the specific observed value (e.g., "admin"). The `double` is the accumulated confidence score for that (Key, Value) pair, building towards a threshold.

-   **Key Data Structure for "Confident" Items:**
    -   `m_confident_sets` (`UMap<Key, ValueSetWithTime>`): A map where `Key` is the item identifier. `ValueSetWithTime` contains a set of `Val`s that have reached the confidence threshold for that `Key`, along with a timestamp of the last update. These are considered the learned baseline of normal/expected values.

-   **Distinguishing Score Types:**
    -   Different types of scores (Payload, URL, Parameter) are distinguished by the string format of the `Key`. This is a convention established by the callers of the `ConfidenceCalculator`.
    -   Examples:
        -   Parameter: `"param#<parameter_name>"` (e.g., `"param#country_code"`)
        -   URL: `"url#<url_pattern_or_exact_url>"` (e.g., `"url#/api/v1/users"`)
        -   Payload-related aspects (e.g., data types, specific field values) would also use a structured `Key` string, like `"payload#dataType#fieldName"`.
    -   The `ConfidenceCalculator` uses this `Key` to group observations and their corresponding scores.

-   **Brief Overview of How a Value Becomes "Confident":**
    1.  **Observation Logging (`ConfidenceCalculator::log()`):**
        -   When a specific `Value` (e.g., "US") is observed for a `Key` (e.g., "param#country_code") from a particular `Source` (e.g., an IP address), this observation is logged in `m_time_window_logger`.
    2.  **Interval Calculation (`ConfidenceCalculator::calculateInterval()`):**
        -   Periodically, this function processes the logged data from the past interval.
        -   For each `(Key, Value)` pair, it calculates how many unique sources observed it, and the ratio of these sources to all unique sources that interacted with the `Key`.
        -   The confidence score `m_confidence_level[Key][Value]` is incremented. The increment amount depends on:
            -   A base value related to `SCORE_THRESHOLD` (target score, e.g., 100.0) and `minIntervals` (number of intervals to reach confidence).
            -   The calculated ratio of sources (higher ratio = bigger increment).
            -   A logarithmic scaling of the number of sources observing the value (more sources increase confidence, but with diminishing returns).
            -   Tuning factors (e.g., if a parameter is marked as benign, its values gain confidence faster).
        -   If a previously known `(Key, Value)` is *not* seen in the current interval, its score in `m_confidence_level` decays, reducing its confidence over time unless reinforced.
    3.  **Reaching Confidence Threshold (`ConfidenceCalculator::calcConfidentValues()`):**
        -   After scores in `m_confidence_level` are updated, this function checks them.
        -   If `m_confidence_level[Key][Value]` reaches the predefined `SCORE_THRESHOLD` (e.g., 100.0), that `Value` is considered "confident" for that `Key`.
        -   The confident `Value` is then added to the `m_confident_sets[Key]`. This set represents the learned baseline of expected values for that specific parameter, URL, or payload characteristic.
    4.  **Usage:**
        -   Other parts of the system can then use `ConfidenceCalculator::is_confident(Key, Value)` to check if a newly observed value is part of this learned baseline. Values not found in the confident set might be considered anomalous or suspicious.
