"""
Log Simulator — AI Threat Hunting & Incident Response Platform
Generates continuous streams of realistic cybersecurity log events,
including normal behavior and scripted attack scenarios.
"""

import json
import random
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Generator

from .generators.auth_logs import generate_login_success, generate_login_failed, generate_password_change
from .generators.system_logs import generate_file_access, generate_admin_access
from .generators.attack_scenarios import (
    BruteForceScenario,
    PrivilegeEscalationScenario,
    DataExfiltrationScenario,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SIMULATOR] %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Normal-behavior probability weights
# ---------------------------------------------------------------------------
NORMAL_EVENT_WEIGHTS = {
    "login_success":     0.40,
    "login_failed":      0.15,
    "file_access":       0.30,
    "admin_access":      0.05,
    "password_change":   0.10,
}

ATTACK_SCENARIO_CLASSES = [
    BruteForceScenario,
    PrivilegeEscalationScenario,
    DataExfiltrationScenario,
]


class LogSimulator:
    """
    Generates a continuous stream of log events mixing normal activity
    with periodic injected attack scenarios.

    Parameters
    ----------
    events_per_second : float
        Target emission rate for normal events.
    attack_probability : float
        Probability (per second) that an attack scenario begins.
    output : str
        One of "stdout", "file", or "kafka".
    output_path : str
        File path used when output="file".
    kafka_topic : str
        Kafka topic used when output="kafka".
    """

    def __init__(
        self,
        events_per_second: float = 5.0,
        attack_probability: float = 0.02,
        output: str = "stdout",
        output_path: str = "logs/simulated.jsonl",
        kafka_topic: str = "raw-logs",
    ):
        self.events_per_second = events_per_second
        self.attack_probability = attack_probability
        self.output = output
        self.output_path = output_path
        self.kafka_topic = kafka_topic

        self._event_generators = {
            "login_success":   generate_login_success,
            "login_failed":    generate_login_failed,
            "file_access":     generate_file_access,
            "admin_access":    generate_admin_access,
            "password_change": generate_password_change,
        }

        self._kafka_producer = None
        if output == "kafka":
            self._kafka_producer = self._init_kafka()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Run the simulator indefinitely, emitting events at the configured rate."""
        logger.info(
            "Simulator started — %.1f events/s, attack_prob=%.2f, output=%s",
            self.events_per_second,
            self.attack_probability,
            self.output,
        )
        interval = 1.0 / self.events_per_second

        for event in self._event_stream():
            self._emit(event)
            time.sleep(interval)

    def generate_batch(self, n: int, include_attacks: bool = True) -> list[dict]:
        """
        Generate a fixed batch of n log events (useful for ML training data export).

        Parameters
        ----------
        n : int
            Number of events to generate.
        include_attacks : bool
            Whether to inject attack scenario events into the batch.

        Returns
        -------
        list[dict]
            Ordered list of log event dicts.
        """
        events = []
        attack_pool = []

        if include_attacks:
            for ScenarioClass in ATTACK_SCENARIO_CLASSES:
                scenario = ScenarioClass()
                attack_pool.extend(scenario.generate())

        for _ in range(n):
            # Occasionally pull from the pre-generated attack pool
            if attack_pool and random.random() < self.attack_probability * 10:
                event = attack_pool.pop(0)
            else:
                event = self._normal_event()
            events.append(event)

        return events

    # ------------------------------------------------------------------
    # Internal stream
    # ------------------------------------------------------------------

    def _event_stream(self) -> Generator[dict, None, None]:
        """Infinite generator: normal events with occasional attack bursts."""
        while True:
            # Decide whether to start an attack scenario this tick
            if random.random() < self.attack_probability:
                ScenarioClass = random.choice(ATTACK_SCENARIO_CLASSES)
                scenario = ScenarioClass()
                logger.warning("Attack scenario triggered: %s", ScenarioClass.__name__)
                for attack_event in scenario.generate():
                    yield attack_event
                    time.sleep(0.1)  # attack events arrive in rapid succession
            else:
                yield self._normal_event()

    def _normal_event(self) -> dict:
        """Pick a random normal event type and generate one log entry."""
        event_types = list(NORMAL_EVENT_WEIGHTS.keys())
        weights     = list(NORMAL_EVENT_WEIGHTS.values())
        chosen_type = random.choices(event_types, weights=weights, k=1)[0]
        return self._event_generators[chosen_type]()

    # ------------------------------------------------------------------
    # Output routing
    # ------------------------------------------------------------------

    def _emit(self, event: dict) -> None:
        if self.output == "stdout":
            print(json.dumps(event))
        elif self.output == "file":
            with open(self.output_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        elif self.output == "kafka" and self._kafka_producer:
            self._kafka_producer.send(
                self.kafka_topic,
                value=json.dumps(event).encode("utf-8"),
                key=event["event_id"].encode("utf-8"),
            )

    def _init_kafka(self):
        try:
            from kafka import KafkaProducer  # type: ignore
            return KafkaProducer(bootstrap_servers=["localhost:9092"])
        except ImportError:
            logger.error("kafka-python not installed. Falling back to stdout.")
            self.output = "stdout"
            return None
