# Contributing

Thank you for helping with afwd. Before you open a pull request, please read the agreement below. By submitting a contribution, you agree to it.

## Why there is an agreement

afwd is published under the GNU Affero General Public License v3.0 (see [LICENSE](LICENSE)). Trilobit, which runs the afwd service, holds the copyright and wants to keep the option to offer afwd under other terms in the future, including closed source. That is only possible if Trilobit has the right to relicense every contribution, so we ask for that right.

You keep the copyright in your contribution and can use it however you like. Versions of afwd that were published under the AGPL stay available under the AGPL.

## Contributor License Agreement

1. **Definitions.** "Trilobit" is Trilobit, the maintainer of afwd. A "Contribution" is any work you submit to this repository for inclusion in afwd, such as code, documentation or other material, by pull request, patch or any other means.

2. **Copyright license.** You grant Trilobit, and anyone who receives software from Trilobit, a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable license to reproduce, modify, prepare derivative works of, publicly display, publicly perform, sublicense and distribute your Contributions and derivative works of them, **under any license terms Trilobit chooses, including proprietary terms**.

3. **Patent license.** You grant Trilobit, and anyone who receives software from Trilobit, a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable patent license to make, have made, use, sell, offer to sell, import and otherwise transfer your Contributions, for any patent claims you can license that your Contribution, alone or combined with afwd, would infringe.

4. **Your right to contribute.** You confirm that each Contribution is your original work and that you have the right to grant these licenses. If your employer or anyone else has rights in your work, you confirm that you have their permission, or that they have waived those rights. If part of a Contribution is not your original work, you say so in the pull request and name its source and license.

5. **No warranty.** You provide your Contributions "as is", without warranties or conditions of any kind. Trilobit is not required to use them.

## How to agree

Every pull request has a checkbox confirming that you have read and agree to this agreement. Pull requests without it checked are not merged.

## Dependencies

New Rust dependencies must use a license on the allow list in [deny.toml](deny.toml). CI checks this with `cargo deny check licenses`. A copyleft dependency would prevent Trilobit from relicensing afwd, so please discuss it in an issue first.
