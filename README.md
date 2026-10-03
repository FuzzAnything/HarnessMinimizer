# HarnessReducer

## Installation

Build the image and create the container from the repository root.

```bash
./setup_docker.sh
```

Enter the container and select the repository directory.

```bash
docker exec -it harnessminimizer-eval bash
cd /root/HarnessMinimizer
```

Run the remaining installation commands from this directory inside the container.

Install the Python package and activate its environment using uv.

```bash
uv sync
source .venv/bin/activate
```

Install the prerequisites for Perses, WDD, CDD.

```bash
apt-get update
apt-get install -y openjdk-17-jdk-headless coreutils unzip zip
```

Install Bazelisk to build the Perses engines.

```bash
mkdir -p .tools/bin
curl -fL --retry 3 \
  https://github.com/bazelbuild/bazelisk/releases/download/v1.29.0/bazelisk-linux-amd64 \
  -o .tools/bin/bazelisk
chmod +x .tools/bin/bazelisk
export PATH="$(pwd)/.tools/bin:$PATH"
```

Build and install the pinned Perses revision.

```bash
mkdir -p .tools/perses
git clone https://github.com/uw-pluverse/perses.git .tools/perses/source
git -C .tools/perses/source checkout --detach 6c6ae0db20fa83b0f85a71ca447f0c4d5e056bd2
python tools/perses/install.py --source .tools/perses/source --jobs 2
```

Install and select patched treereduce.

```bash
python tools/treereduce/install.py
export HARNESSREDUCER_TREEREDUCE="$(pwd)/.tools/bin/treereduce-c"
```

## Reduce a harness

Run from the directory containing `harness.cpp` and `crash-input`; replace `target` with the target library name.

Enable all optimizations.

```bash
harnessreducer harness.cpp \
  --compile-flags="-I$(pwd)/build/sanitizer/include" \
  --link-flags="-L$(pwd)/build/sanitizer/lib -ltarget" \
  --crash-input crash-input \
  --pch --amortize-link --stable \
  -o reduced.optimized.cpp
```

Disable all optimizations.

```bash
harnessreducer harness.cpp \
  --compile-flags="-I$(pwd)/build/sanitizer/include" \
  --link-flags="-L$(pwd)/build/sanitizer/lib -ltarget" \
  --crash-input crash-input \
  --split --symbolize --stable \
  -o reduced.baseline.cpp
```

## Evaluation

Run these commands from the repository root with the benchmark data available under `benchmark/`.

Run performance evaluation for all four engines across both datasets.

```bash
./run_harnessreducer_evaluation.sh --tool all
```

Create the crash-triage configuration.

```bash
cp .env-template .env
```

Fill in `OPENAI_BASE_URL`, `LLM_API_KEY`, and `OPENAI_MODEL` in `.env`.

Run crash triage with n worker using the latest performance evaluation batch (n parallel requests to LLM).

```bash
./run_crash_triage_parallel.sh --tool all --jobs n
```

Retry failed or unfinished triage cases with n workers (timeout or LLM failing to follow the instructions).

```bash
./run_crash_triage_parallel.sh --tool all --jobs n --resume
```
