# /analyze - RAPTOR LLM Analysis

⚠️ **LLM-POWERED ANALYSIS** - This will:
1. Validate each vulnerability (true positive check)
2. Assess exploitability (scoring + attack scenarios)
3. Generate exploit PoCs
4. Generate secure patches

**Time:** ~30-60 seconds per vulnerability (LLM calls)
**Cost:** ~$0.01-0.03 per vulnerability (Claude/GPT-4)

For 10 findings: ~5-10 minutes, ~$0.10-0.30

Execute: `python3 raptor.py analyze --repo <path> --sarif <sarif-file> --max-findings <N>`

**Limit findings to control time/cost:** Use `--max-findings 5` for faster analysis.
