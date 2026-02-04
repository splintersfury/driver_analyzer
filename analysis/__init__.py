"""
driver_analyzer.analysis

Semantic analysis modules for driver vulnerability detection.
"""

from .code_normalizer import normalize_decompiled_code, parse_decompiled_functions
from .semantic_rule_engine import SemanticRuleEngine, RuleHit, SinkMatch
from .semantic_diff import SemanticDiffEngine, SemanticDiffResult, SemanticFinding
from .patch_scorer import PatchScorer, ScoredFinding, ScoreBreakdown
from .report_generator import ReportGenerator
from .timeline import TimelineGenerator, VersionPoint

__all__ = [
    # Code normalizer
    'normalize_decompiled_code',
    'parse_decompiled_functions',

    # Semantic rule engine
    'SemanticRuleEngine',
    'RuleHit',
    'SinkMatch',

    # Semantic diff
    'SemanticDiffEngine',
    'SemanticDiffResult',
    'SemanticFinding',

    # Patch scorer
    'PatchScorer',
    'ScoredFinding',
    'ScoreBreakdown',

    # Report generator
    'ReportGenerator',

    # Timeline
    'TimelineGenerator',
    'VersionPoint',
]
