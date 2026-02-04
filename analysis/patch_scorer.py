"""
Patch Scorer - Stage 6 Implementation

Scores and ranks semantic findings using the scoring.yaml model.
"""

import os
import yaml
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from .semantic_diff import SemanticFinding

logger = logging.getLogger("driver_analyzer.patch_scorer")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SCORING_PATH = os.path.join(PROJECT_ROOT, "rules", "scoring.yaml")


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of a finding's score."""
    semantic_contributions: List[Dict[str, Any]]
    reachability: Dict[str, Any]
    sinks: Dict[str, Any]
    penalties: Dict[str, float]
    total_before_clamp: float
    total_after_clamp: float
    gates_triggered: List[str]


@dataclass
class ScoredFinding:
    """A finding with its computed score."""
    finding: SemanticFinding
    final_score: float
    breakdown: ScoreBreakdown
    rank: int = 0


class PatchScorer:
    """
    Scores semantic findings using the scoring.yaml model.

    Score composition:
    - semantic_score = sum(rule_base_weight * confidence) * category_multiplier
    - reachability_score = reachability_bonus * confidence_adjusted
    - sink_score = sum(sink_bonus[group]) * min(1.0, semantic_confidence)
    - penalties = pairing + noise_risk + matching_quality
    - final = clamp(semantic + reachability + sink - penalties, 0.0, 15.0)
    """

    def __init__(self, scoring_path: str = None):
        """
        Initialize the scorer.

        Args:
            scoring_path: Path to scoring.yaml
        """
        scoring_path = scoring_path or DEFAULT_SCORING_PATH

        with open(scoring_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.weights = self.config.get('weights', {})
        self.gating = self.config.get('gating', {})
        self.composition = self.config.get('composition', {})

        # Extract weight tables
        self.rule_weights = self.weights.get('semantic_rule_base', {})
        self.category_multipliers = self.weights.get('category_multiplier', {})
        self.reachability_bonuses = self.weights.get('reachability_bonus', {})
        self.sink_bonuses = self.weights.get('sink_bonus', {})
        self.penalties = self.weights.get('penalties', {})

        # Clamp values
        self.min_score = self.composition.get('clamp', {}).get('min', 0.0)
        self.max_score = self.composition.get('clamp', {}).get('max', 15.0)
        self.max_findings = self.composition.get('max_findings_in_report', 10)

        logger.info(f"PatchScorer initialized with {len(self.rule_weights)} rule weights")

    def score_findings(self, findings: List[SemanticFinding],
                       matching_confidence: float = 0.80,
                       pairing_decision: str = "accept",
                       noise_risk: str = "low",
                       matching_quality: str = "high") -> List[ScoredFinding]:
        """
        Score and rank a list of semantic findings.

        Args:
            findings: List of SemanticFinding objects
            matching_confidence: Function matching confidence (0-1)
            pairing_decision: 'accept', 'quarantine', or 'reject'
            noise_risk: 'low', 'medium', or 'high'
            matching_quality: 'high', 'medium', or 'low'

        Returns:
            List of ScoredFinding objects, sorted by score descending
        """
        scored = []

        for finding in findings:
            score, breakdown = self._score_single(
                finding,
                matching_confidence,
                pairing_decision,
                noise_risk,
                matching_quality
            )

            # Apply gating
            gates = []
            gated_score = score

            # Matching confidence gate
            mc_gate = self.gating.get('matching_confidence', {})
            if matching_confidence < mc_gate.get('min_required', 0.40):
                cap = mc_gate.get('cap_if_below', 3.0)
                if score > cap:
                    gated_score = cap
                    gates.append(f"matching_confidence < {mc_gate.get('min_required')}")

            # Semantic confidence gate
            sc_gate = self.gating.get('semantic_confidence', {})
            if finding.confidence < sc_gate.get('hard_min', 0.45):
                if sc_gate.get('drop_if_below_hard_min', True):
                    continue  # Drop this finding
                gates.append(f"semantic_confidence < {sc_gate.get('hard_min')}")

            if finding.confidence < sc_gate.get('soft_min', 0.60):
                cap = sc_gate.get('cap_if_below_soft_min', 5.0)
                if gated_score > cap:
                    gated_score = cap
                    gates.append(f"semantic_confidence < {sc_gate.get('soft_min')}")

            breakdown.gates_triggered = gates
            breakdown.total_after_clamp = gated_score

            scored.append(ScoredFinding(
                finding=finding,
                final_score=gated_score,
                breakdown=breakdown
            ))

        # Sort by score descending
        scored.sort(key=lambda x: x.final_score, reverse=True)

        # Assign ranks and limit
        for i, sf in enumerate(scored[:self.max_findings]):
            sf.rank = i + 1

        return scored[:self.max_findings]

    def _score_single(self, finding: SemanticFinding,
                      matching_confidence: float,
                      pairing_decision: str,
                      noise_risk: str,
                      matching_quality: str) -> tuple:
        """Score a single finding."""

        semantic_contributions = []
        total_semantic = 0.0

        # Semantic score from rule
        rule_weight = self.rule_weights.get(finding.rule_id, 3.0)
        contribution = rule_weight * finding.confidence
        semantic_contributions.append({
            'rule_id': finding.rule_id,
            'base_weight': rule_weight,
            'confidence': finding.confidence,
            'contribution': contribution
        })
        total_semantic += contribution

        # Category multiplier
        cat_mult = self.category_multipliers.get(finding.category, 1.0)
        total_semantic *= cat_mult

        # Reachability score
        reach_bonus = self.reachability_bonuses.get(finding.reachability_class, 0.0)

        # Adjust reachability by confidence
        rc_gate = self.gating.get('reachability_confidence', {})
        reach_mult = 1.0
        if matching_confidence < rc_gate.get('soft_min', 0.55):
            reach_mult = rc_gate.get('multiplier_if_below', 0.70)

        reachability_score = reach_bonus * reach_mult
        reachability_info = {
            'class': finding.reachability_class,
            'bonus': reach_bonus,
            'multiplier': reach_mult,
            'contribution': reachability_score
        }

        # Sink score
        sink_total = 0.0
        sink_details = {}
        for sink_group in finding.sinks:
            bonus = self.sink_bonuses.get(sink_group, 0.0)
            sink_total += bonus
            sink_details[sink_group] = bonus

        # Scale sink score by semantic confidence
        sink_score = sink_total * min(1.0, finding.confidence)
        sinks_info = {
            'groups': sink_details,
            'raw_total': sink_total,
            'confidence_scaled': sink_score
        }

        # Penalties
        penalty_total = 0.0
        penalty_details = {}

        # Pairing decision penalty
        pd_penalties = self.penalties.get('pairing_decision', {})
        pd_pen = pd_penalties.get(pairing_decision, 0.0)
        if pd_pen < 100:  # Skip rejected
            penalty_total += pd_pen
            penalty_details['pairing_decision'] = pd_pen

        # Noise risk penalty
        nr_penalties = self.penalties.get('noise_risk', {})
        nr_pen = nr_penalties.get(noise_risk, 0.0)
        penalty_total += nr_pen
        penalty_details['noise_risk'] = nr_pen

        # Matching quality penalty
        mq_penalties = self.penalties.get('matching_quality', {})
        mq_pen = mq_penalties.get(matching_quality, 0.0)
        penalty_total += mq_pen
        penalty_details['matching_quality'] = mq_pen

        # Final score
        total = total_semantic + reachability_score + sink_score - penalty_total
        clamped = max(self.min_score, min(self.max_score, total))

        breakdown = ScoreBreakdown(
            semantic_contributions=semantic_contributions,
            reachability=reachability_info,
            sinks=sinks_info,
            penalties=penalty_details,
            total_before_clamp=total,
            total_after_clamp=clamped,
            gates_triggered=[]
        )

        return clamped, breakdown

    def to_dict(self, scored_finding: ScoredFinding) -> Dict[str, Any]:
        """Convert ScoredFinding to dictionary for JSON serialization."""
        return {
            'function': scored_finding.finding.function,
            'rule_id': scored_finding.finding.rule_id,
            'category': scored_finding.finding.category,
            'confidence': scored_finding.finding.confidence,
            'sinks': scored_finding.finding.sinks,
            'indicators': scored_finding.finding.indicators,
            'why_matters': scored_finding.finding.why_matters,
            'reachability_class': scored_finding.finding.reachability_class,
            'final_score': scored_finding.final_score,
            'rank': scored_finding.rank,
            'score_breakdown': {
                'semantic': scored_finding.breakdown.total_before_clamp -
                           scored_finding.breakdown.reachability['contribution'] -
                           scored_finding.breakdown.sinks['confidence_scaled'] +
                           sum(scored_finding.breakdown.penalties.values()),
                'reachability': scored_finding.breakdown.reachability['contribution'],
                'sinks': scored_finding.breakdown.sinks['confidence_scaled'],
                'penalties': sum(scored_finding.breakdown.penalties.values()),
                'gates': scored_finding.breakdown.gates_triggered
            }
        }
