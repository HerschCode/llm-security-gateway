"""
Guard-model baselines: comparing this project's from-scratch ensemble against published,
purpose-built prompt-injection detectors. Kept as an optional extra (`pip install .[baselines]`)
because it pulls in `transformers` + a ~700MB model download, the exact torch-on-Render-512MB
problem the core serving path (`gateway/detectors/classifier_numpy.py`) was built to avoid.
Nothing here is imported by `gateway/`; it is a research/reporting tool only.
"""
