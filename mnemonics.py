from bip_utils import (
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip39MnemonicGenerator,
    Bip39WordsNum,
    AtomAddrEncoder,
)

import multiprocessing
import base64


def main():
    num_processes = 16
    pool = multiprocessing.Pool(processes=num_processes)

    for i in range(num_processes):
        new_process = multiprocessing.Process(target=search, args=())
        new_process.start()
    # search()


def search():
    while True:
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)

        seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
        bip44_def_ctx = Bip44.FromSeed(
            seed_bytes, Bip44Coins.COSMOS
        ).DeriveDefaultPath()
        addr = AtomAddrEncoder.EncodeKey(
            bip44_def_ctx.PublicKey().RawCompressed().ToBytes(), hrp="fetch"
        )

        if (
            addr.startswith("fetch1234567")
            or addr.startswith("fetch1sweep")
            or addr.startswith("fetch1c0sm0s")
            or addr.startswith("fetch1c0smjs")
            or addr.startswith("fetch1c0smpy")
            or addr.startswith("fetch1d0rad0")
            or addr.startswith("fetch1f0rmax")
            or addr.startswith("fetch1faucet")
            or addr.startswith("fetch1ledger")
            or addr.startswith("fetch1sentry")
            or addr.startswith("fetch1tested")
            or addr.startswith("fetch1tester")
            or addr.startswith("fetch1wallet")
            or addr.startswith("fetch1fetch")
            or addr.startswith("fetch1snaps")
            or addr.startswith("fetch1authz")
            # or addr.startswith("fetch1t")
        ):

            key = base64.b64encode(bip44_def_ctx.PrivateKey().Raw().ToBytes()).decode(
                "utf-8"
            )
            f = open("keys.txt", "a")
            f.write(f'{addr} = PrivateKey("{key}") # {mnemonic}\n')
            f.close()
            print(f"{addr}")


if __name__ == "__main__":
    main()
