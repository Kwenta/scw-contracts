# scw-contracts

[![Github Actions][gha-badge]][gha]
[![Foundry][foundry-badge]][foundry]
[![License: GPL-3.0][license-badge]][license]

[gha]: https://github.com/Kwenta/scw-contracts/actions
[gha-badge]: https://github.com/Kwenta/scw-contracts/actions/workflows/test.yml/badge.svg
[foundry]: https://getfoundry.sh/
[foundry-badge]: https://img.shields.io/badge/Built%20with-Foundry-FFDB1C.svg
[license]: https://opensource.org/license/GPL-3.0/
[license-badge]: https://img.shields.io/badge/GitHub-GPL--3.0-informational

## Overview

scw-contracts is a collection of modified [Biconomy](https://github.com/bcnmy/scw-contracts) contracts used by Kwenta. Specifically, Kwenta required a modified version of the [Session Validation Module](https://github.com/bcnmy/scw-contracts/tree/master/contracts/smart-account/modules/SessionValidationModules) to support [Account Abstraction](https://www.biconomy.io). The Session Validation Module is used to validate the details of a [User Operation](https://github.com/bcnmy/account-abstraction/blob/develop/contracts/interfaces/UserOperation.sol) that defines an interaction between an actor and Kwenta's [Smart Margin v2](https://github.com/Kwenta/smart-margin) or [Smart Margin v3](https://github.com/Kwenta/smart-margin-v3) system.

## Contracts

> `tree src/`

```
src/
├── SMv2SessionValidationModule.sol
├── SMv3SessionValidationModule.sol
├── biconomy
│   ├── BaseAuthorizationModule.sol
│   └── interfaces
│       ├── IAuthorizationModule.sol
│       ├── ISessionValidationModule.sol
│       ├── ISignatureValidator.sol
│       └── UserOperation.sol
├── kwenta
│   ├── smv2
│   │   └── IAccount.sol
│   └── smv3
│       ├── IERC7412.sol
│       └── IEngine.sol
└── openzeppelin
    └── ECDSA.sol
```

## Tests

1. Follow the [Foundry guide to working on an existing project](https://book.getfoundry.sh/projects/working-on-an-existing-project.html)

2. Build project

```
npm run compile
```

3. Execute tests (requires rpc url(s) to be set in `.env`)

```
npm run test
```

4. Run specific test
    > `OPTIMISM_SEPOLIA_RPC_URL` can be replaced with `OPTIMISM_RPC_URL` if a mainnet fork is desired

```
forge test --fork-url $(grep OPTIMISM_SEPOLIA_RPC_URL .env | cut -d '=' -f2) --match-test TEST_NAME -vvv
```

## Deployment Addresses

> See `deployments/` folder

1. Optimism deployments found in `deployments/Optimism.json`
2. Optimism Sepolia deployments found in `deployments/OptimismSepolia.json`
3. Base deployments found in `deployments/Base.json`
4. Base Sepolia deployments found in `deployments/BaseSepolia.json`

## Audits

> See `audits/` folder

1. Internal audits found in `audits/internal/`
2. External audits found in `audits/external/`
