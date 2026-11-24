<p align="center">
  <a href="https://hedlo.io/marketplace">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="assets/hedlo-logo-dark.svg">
      <img src="assets/hedlo-logo.svg" alt="Hedlo" width="222" height="64">
    </picture>
  </a>
</p>

<h1 align="center">Hedlo SDK</h1>

<p align="center">The command line tool and library for publishing to the Hedlo Marketplace.</p>

<p align="center">
  <a href="https://hedlo.io/marketplace">Marketplace</a> &nbsp;|&nbsp;
  <a href="https://hedlo.io/docs/marketplace/cli">CLI guide</a> &nbsp;|&nbsp;
  <a href="https://hedlo.io/docs/marketplace/publishing">Publishing</a> &nbsp;|&nbsp;
  <a href="https://hedlo.io/docs/marketplace/licensing">Licensing</a>
</p>

The Hedlo Marketplace is where hosts find plugins, themes and templates for Loom and Bolt. This repository contains the tools that publishers use to build, check and release those packages, and the library that Loom and Bolt use to install them and verify their licences.

## Packages

| Package | Purpose |
| --- | --- |
| `@hedlo/cli` | The `hedlo` command for publishers |
| `@hedlo/market` | Package archives, manifests, signatures, licence verification and the automated review checks |

## The hedlo command

```sh
npm install --global @hedlo/cli
hedlo login
```

Sign-in uses a device code, so you confirm it in the browser and never paste a password into the terminal. In continuous integration, set `HEDLO_TOKEN` to a token from your publisher dashboard instead.

A typical release looks like this:

```sh
hedlo init
hedlo validate
hedlo publish --notes CHANGELOG.md
hedlo status
```

`hedlo validate` runs the same checks as the marketplace review before anything is uploaded. `hedlo compat` tests your items against the current Loom and Bolt releases. The command also manages listings, prices, discounts, advisories, reviews, support threads, sales and payouts. Run `hedlo help` or read the [CLI guide](https://hedlo.io/docs/marketplace/cli) for the full list.

## The library

`@hedlo/market` is what Loom and Bolt use, through Hedlo Kit, to install packages. It reads and verifies package archives, checks the publisher signature and the licence for the site, and runs the same automated review that the marketplace applies on upload. It also contains the pricing, ledger and ranking rules the marketplace uses, so publishers and hosts can see exactly how fees and payouts are calculated. Publishers can use it in their own build tooling.

```sh
npm install @hedlo/market
```

Node.js 22 or newer is required.

## Security

Please report vulnerabilities privately. The process and contact details are on [hedlo.io/security](https://hedlo.io/security).

## License

The Hedlo SDK is open source. The license is published with the first release. The marketplace service itself is operated by Hedlo and is not part of this repository.
