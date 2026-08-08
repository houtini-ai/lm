# Getting started: local models, endpoints, and hardware

This guide takes you from nothing to a working local endpoint that houtini-lm
can delegate to. It covers two paths — **LM Studio** (easiest, desktop) and
**Docker** (headless servers) — how to point houtini at either, and a practical
primer on which models to run on the hardware you have.

If you already have an OpenAI-compatible endpoint, skip to
[Pointing houtini at your endpoint](#pointing-houtini-at-your-endpoint).

---

## Path A — LM Studio (easiest, desktop)

LM Studio is a desktop app (macOS / Windows / Linux) with a built-in
OpenAI-compatible server. It's the fastest way to get running, and on Apple
Silicon it uses the MLX runtime, which is excellent.

1. **Install** — download from [lmstudio.ai](https://lmstudio.ai) and run the
   installer. It's a normal desktop app; no command line needed.
2. **Download a model** — open the 🔍 *Discover* tab, search for a model (e.g.
   `Qwen2.5-Coder-32B-Instruct`), and pick a **GGUF** quant. `Q4_K_M` is the
   usual sweet spot (see [Choosing a quant](#choosing-a-quant)). LM Studio shows
   an estimate of whether it fits your machine before you download.
3. **Load it** — go to the 💬 *Chat* tab (or the *Developer* tab), select the
   model from the top bar, and let it load into memory.
4. **Start the server** — open the *Developer* (or *Local Server*) tab and click
   **Start Server**. By default it listens on `http://localhost:1234` and speaks
   the OpenAI `/v1/chat/completions` API. That's the endpoint houtini uses.
5. **Point houtini at it** — nothing to configure if it's the default:

   ```bash
   claude mcp add houtini-lm -- npx -y @houtini/lm
   ```

   If LM Studio runs on another machine on your network:

   ```bash
   claude mcp add houtini-lm \
     -e HOUTINI_LM_ENDPOINT_URL=http://192.168.1.50:1234 \
     -- npx -y @houtini/lm
   ```

> **Headless LM Studio.** LM Studio ships a CLI (`lms`) that can run the server
> without the GUI (`lms server start`), useful on a dedicated box you SSH into.
> It still isn't a container — for Docker, use Path B.

---

## Path B — Docker (headless servers)

**LM Studio does not run in Docker** — it's a GUI/Electron app. For a
containerised, headless endpoint use one of the engines below. All three expose
the same OpenAI-compatible API that houtini talks to, so from houtini's side they
are interchangeable.

> **GPU passthrough:** the `--gpus all` flag needs NVIDIA's
> [container toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
> installed on the host. **Docker cannot use an Apple Silicon GPU (Metal)** — on
> a Mac, run LM Studio or Ollama natively instead of in Docker.

### Ollama (simplest)

```bash
docker run -d --gpus=all -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
docker exec -it ollama ollama pull qwen2.5-coder:32b
```

Endpoint: `http://localhost:11434` — point houtini at it:

```bash
claude mcp add houtini-lm -e HOUTINI_LM_ENDPOINT_URL=http://localhost:11434 -- npx -y @houtini/lm
```

houtini auto-detects Ollama and handles its `delta.reasoning` channel and thinking
models transparently.

### llama.cpp server (lightweight, GGUF)

```bash
docker run -d --gpus all -p 8080:8080 -v ~/models:/models \
  ghcr.io/ggml-org/llama.cpp:server-cuda \
  -m /models/qwen2.5-coder-32b-instruct-q4_k_m.gguf \
  -c 16384 --host 0.0.0.0 --port 8080 -ngl 999
```

Endpoint: `http://localhost:8080` (`-ngl 999` offloads all layers to GPU; lower
it to split across CPU+GPU for a model that doesn't quite fit).

### vLLM (throughput / serving many parallel requests)

```bash
docker run -d --gpus all -p 8000:8000 \
  vllm/vllm-openai --model Qwen/Qwen2.5-Coder-32B-Instruct
```

Endpoint: `http://localhost:8000`. vLLM shines when several agents hit it
concurrently — relevant if you're running houtini under a multi-agent
orchestrator.

---

## Pointing houtini at your endpoint

houtini needs one thing: the base URL of an OpenAI-compatible server. Auth and
model pinning are optional.

| Variable | Default | What it does |
|----------|---------|--------------|
| `HOUTINI_LM_ENDPOINT_URL` | `http://localhost:1234` | Base URL of the endpoint |
| `HOUTINI_LM_API_KEY` | *(none)* | Bearer token, if the endpoint needs one |
| `HOUTINI_LM_MODEL` | *(auto)* | Pin a specific model id; blank = use whatever's loaded |

```bash
claude mcp add houtini-lm \
  -e HOUTINI_LM_ENDPOINT_URL=http://localhost:8080 \
  -- npx -y @houtini/lm
```

**Verify it works:** ask Claude to run the `discover` tool. A healthy setup
reports `Status: ONLINE`, the active model, its context window, and — after the
first real call — its measured speed. If it says `no model loaded`, load a model
in your engine first.

---

## Understanding local models: what the small ones are good at

Local models trade capability for privacy, cost, and control. The delegation
mindset is: **send bounded, self-contained work the model can do reliably, and
verify the output.** Capability scales with size, roughly in three bands.

**Small (≤ 14B) — fast and cheap, mechanical work.** These are excellent at
tasks with a clear input and a clear output shape: boilerplate, test stubs,
format conversion (JSON↔YAML, snake_case↔camelCase), regexes, single-function
explanations, commit messages, extraction/classification, and simple refactors.
They're weak at multi-file reasoning, novel algorithms, subtle bug-hunting, and
long-context synthesis. Give them complete context and a strict output contract.

**Mid (24–32B) — the delegation sweet spot.** Code-specialised models in this
band (e.g. Qwen2.5-Coder-32B) are useful for real code review, test
generation, and multi-function refactors. This is where most people get the best
ratio of capability to hardware cost. Still verify before committing.

**Large (70B+) — approaching frontier for bounded tasks.** Better judgment,
fewer hallucinations, more reliable on subtle issues and longer context. The
cost is speed and VRAM.

A few cross-cutting notes:

- **MoE (mixture-of-experts) models** — e.g. `Qwen3-30B-A3B` (30B total, 3B
  *active*) — run much faster than a dense model of the same total size because
  only a slice of the weights fire per token. But you still need the **full**
  weights in VRAM. Great when you have the memory but want speed.
- **Reasoning/"thinking" models** (DeepSeek-R1 distills, etc.) reason better but
  are slower and spend part of their token budget on hidden reasoning. houtini
  suppresses that thinking by default to keep delegation fast — good for bounded
  tasks, less so when you actually want the deliberation.
- **Verify, always.** Local capability varies; houtini's response footer surfaces
  quality signals (truncation, token estimates, measured speed) precisely so the
  orchestrator can decide when to trust or re-run a result.

### Choosing a quant

Quantisation shrinks a model to fit VRAM at some quality cost. Practical guidance:

- **`Q4_K_M` / 4-bit** — the standard sweet spot; near-full quality at ~half the
  memory of 8-bit. Start here.
- **`Q6_K` / `Q8_0`** — higher fidelity when you have VRAM to spare; diminishing
  returns above Q6 for most tasks.
- **Below Q4** (`Q3`, `Q2`) — only when you must squeeze a bigger model in;
  quality degrades noticeably. Often a smaller model at Q4 beats a bigger one at Q2.

---

## Which models fit your VRAM

Approximate guidance, assuming **4-bit** weights and leaving ~20–30 % headroom
for the KV cache (long context eats VRAM fast). The model landscape moves
quickly — treat these as a starting point and check a current leaderboard
before committing.

> **Apple Silicon note:** unified memory is shared between CPU and GPU, so usable
> "VRAM" is roughly 65–75 % of total. A 128 GB Mac Studio behaves like ~90 GB of
> GPU memory for these purposes. **CPU+GPU offload** (llama.cpp / LM Studio) also
> lets you run a model larger than VRAM, trading speed for capacity.

| VRAM | Comfortable class (4-bit) | Representative SOTA-ish picks (early 2026) | Best suited to |
|------|---------------------------|--------------------------------------------|----------------|
| **16 GB** | 7B–14B dense, or a small MoE | Qwen2.5-Coder-14B · Qwen3-14B · Phi-4 (14B) · Gemma 3 12B · Llama 3.1 8B · DeepSeek-R1-Distill-Qwen-14B · gpt-oss-20b (MoE, ~3.6B active) | Autocomplete, boilerplate, single-file review, chat, extraction |
| **32 GB** | up to 32B dense | **Qwen2.5-Coder-32B** · Qwen3-32B · Qwen3-30B-A3B (fast MoE) · GLM-4-32B · Gemma 3 27B · Mistral Small 3 (24B) · DeepSeek-R1-Distill-Qwen-32B | Real code review, test generation, multi-function refactors — the delegation sweet spot |
| **64 GB** | 70B dense, or larger MoE | Llama 3.3 70B · DeepSeek-R1-Distill-Llama-70B · Llama 4 Scout (109B MoE, 17B active) · a 32B at Q8 + long context | Stronger judgment, subtle bugs, longer context |
| **96 GB** | 70B at higher quant, or 100–120B MoE | gpt-oss-120b (~5B active MoE) · GLM-4.5-Air · Llama 4 Scout with headroom · Llama 3.3 70B at Q6/Q8 | Everything mid-tier plus long-context multi-file work |
| **128 GB** | 120B-class comfortably; 235B MoE tight | Mistral Large 2 (123B) · Command R+ (104B) · gpt-oss-120b at higher precision · Qwen3-235B-A22B (MoE, 22B active — tight at 4-bit, better with offload) | Highest local capability short of a multi-GPU rig |

**Beyond 128 GB:** frontier open-weight models like DeepSeek-V3/R1 (671B) and
Llama 4 Maverick (~400B MoE) need multi-GPU servers or heavy CPU offload. At that
point a hosted OpenAI-compatible API (DeepSeek, Groq, Cerebras, OpenRouter — all
supported, see the README) is usually the pragmatic choice, and houtini talks to
those exactly the same way.

---

## Where to go next

- [README](../README.md) — full tool reference, routing, and configuration
- [DEVELOPER.md](../DEVELOPER.md) — internals, backend detection, the performance cache
- Run the `discover` and `list_models` tools once you're connected — houtini
  auto-profiles whatever you've loaded and tells you what each model is good at.
