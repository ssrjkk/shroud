# Shroud

> **Языки:** [English](README.md) · [Русский](README.ru.md)

Исследовательский протокол для обучения моделей над зашифрованными данными на
fhEVM: эскроу задач, proof-of-compute, потоковые выплаты и пороговое расшифрование.

> **Это исследовательский прототип, а не аудированная система. Не используйте его
> с реальными средствами или приватными данными.** Текущая проверка вычислений —
> fraud-proof/re-execution commitment, а не полная on-chain STARK-верификация.

**Сайт:** https://ssrjkk.github.io/shroud/

## Возможности

- Контракты эскроу и жизненного цикла задачи на Solidity.
- TypeScript SDK для загрузки данных, публикации весов и мониторинга задач.
- Rust-узел вычислений с детерминированным reference engine.
- Хранилище ShardStore и Docker devnet.
- Telegram-бот для операционного мониторинга.
- Статический сайт с протоколом, лабораторией и честным статусом безопасности.

## Быстрый старт без Docker

Нужен Node.js 22. В двух терминалах:

```bash
cd packages/contracts
npm ci
npx hardhat node --hostname 127.0.0.1 --port 8545
```

```bash
cd packages/contracts
npm run deploy:devnet
npm run devnet:e2e
npm run devnet:admin
cd ../sdk
npm ci
npm run build
npm run devnet:sdk
```

Это проверяет согласованность контрактов, адресной книги и SDK на mock
coprocessor; оно не доказывает работоспособность FHE-вычислений.

## Проверки

```bash
cd packages/contracts && npm ci && npx hardhat compile && npx hardhat test
cd ../sdk && npm ci && npm test
cd ../bot && npm ci && npm test
cd ../node && cargo check --all-features && cargo test --all-features
cd ../web && python -m http.server 4173
```

## Документация

- [Архитектура](docs/01-architecture.md)
- [Криптография](docs/02-cryptography.md)
- [Proof of compute](docs/03-proof-of-compute.md)
- [Модель угроз](docs/04-threat-model.md)
- [Ограничения](docs/05-honest-limitations.md)
- [Devnet и эксплуатация](infra/README.md)
- [Безопасность](SECURITY.md)

## Лицензия

MIT — см. [LICENSE](LICENSE).
