<h1 align="center">Authenticated Implicit Flow (AIF)</h1>
<p align="center">Welcome to the code repository for our <a href="https://petsymposium.org/2023/files/papers/issue4/popets-2023-0100.pdf">PETS'23 paper</a>:<p/> 
<p align="center"><i>Save The Implicit Flow? Enabling Privacy-Preserving RP Authentication in OpenID Connect.</i></p>

-------

This repository contains the implementation and benchmarks of the $\mathsf{AIF_{SIG}}$, $\mathsf{AIF_{COM}}$, and
$\mathsf{AIF_{ZKP}}$ constructions, as presented in our paper. The corresponding scheme implementations can be
found in the [src/schemes](src/schemes) directory.

Note that the commitment scheme $\mathsf{COM}$ utilizes Pedersen commitments, which can be accessed through the
following resources:

- Paper: [C:Pedersen91](https://link.springer.com/chapter/10.1007/3-540-46766-1_9)
- Code: [src/building-blocks/com/pc.js](src/building-blocks/com/pc.js)

For the multi-message signature scheme $\mathsf{MMS}$ with efficient proofs, we employ PS signatures. The related
information can be accessed through the following resources:

- Paper: [RSA:PoiSan16](https://inria.hal.science/hal-01377997/file/525.pdf)
- Code: [src/building-blocks/mms/ps.js](src/building-blocks/mms/ps.js)

If you utilize our code implementation or draw insights from our paper, we kindly request that you cite our work
accordingly.

```bibtex
@inproceedings{PETS:KroLeh23,
  author    = {Maximilian Kroschewski and Anja Lehmann},
  title     = {Save The Implicit Flow? Enabling Privacy-Preserving RP Authentication in OpenID Connect},
  booktitle = {},
  pages     = {},
  publisher = {},
  year      = {2023},
  doi       = {}
}
```

## Setup

To ensure a smooth experience, please make sure you have the following prerequisites installed in your environment:

- Node.js
- npm
- (Optional) Docker

Follow the steps below to set up the repository:

1. Clone this repository to your local environment.
2. Run the command `npm install` to install the necessary dependencies.

## Benchmark

You have the option to run the benchmarks either locally or within a Docker container. The following flags can be
provided to customize the benchmark execution:

```
# Set the number of executions; default is 100
BENCHMARK_COUNT=1

# Use optimized proofs (AIF_ZKP only); default is 0
OPTIMIZED_PROOFS=1

# Dev-flag that excludes all RSA operations; default is 0
WITHOUT_RSA=1
```

### Locally

Execute the benchmarks locally using the following commands:

```bash
# Example without flags
npm run benchmark

# Examples with flags
BENCHMARK_COUNT=1 OPTIMIZED_PROOFS=0 WITHOUT_RSA=0 npm run benchmark
BENCHMARK_COUNT=1 OPTIMIZED_PROOFS=1 npm run benchmark
```

### Docker

If you prefer to use Docker, build the image first. This step is only required once:

```bash
docker build -t aif .
```

Run the container using the command:

```bash 
docker run -e BENCHMARK_COUNT=10 -e OPTIMIZED_PROOFS=1 aif npm run benchmark
```

## Tests

The tests for the building blocks can be found in the [tests/building-blocks](tests/building-blocks) directory, while
the tests for the schemes are located in [tests/schemes](tests/schemes). You can execute all tests by running the
following command:

```bash
npm test
```