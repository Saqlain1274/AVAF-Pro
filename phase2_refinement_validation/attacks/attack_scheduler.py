# """
# ===============================================================================

# AVAF Pro

# Attack Scheduler

# Purpose
# -------
# Coordinates the complete validation and refinement lifecycle.

# It is responsible for:

#     • Selecting attack strategies
#     • Executing replay plans
#     • Running algorithms
#     • Collecting evidence
#     • Calling the decision engine

# ===============================================================================
# """

# from __future__ import annotations


# class AttackScheduler:

#     def __init__(

#         self,

#         strategy_registry,

#         replay_engine,

#         algorithms,

#         evidence_collector,

#         voting_engine,

#     ):

#         self.strategy_registry = strategy_registry

#         self.replay_engine = replay_engine

#         self.algorithms = algorithms

#         self.evidence_collector = evidence_collector

#         self.voting_engine = voting_engine

#     def execute(

#         self,

#         candidate,

#     ):

#         strategy = self.strategy_registry.get(

#             candidate.attack_type

#         )

#         attack_plan = strategy.create_attack_plan(

#             candidate

#         )

#         replay_context = self.replay_engine.execute(

#             attack_plan

#         )

#         algorithm_results = []

#         for algorithm in self.algorithms:

#             result = algorithm.analyze(

#                 replay_context

#             )

#             algorithm_results.append(

#                 result

#             )

#             self.evidence_collector.collect(

#                 result

#             )

#         decision = self.voting_engine.decide(

#             algorithm_results

#         )

#         return decision