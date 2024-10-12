#!/bin/sh
# =============================================================================
#  This script runs both the C and Golang implementations of Argon2id and
#  compares the results. It will exit as 0 if the hashes are the same.
#
#  This is the entrypoint for the Docker_clang.
# =============================================================================

# Generate a random salt
# shellcheck disable=SC3028 # POSIX sh does not support $RANDOM but ash in Alpine does
salt="${RANDOM}${RANDOM}"
echo "Salt: ${salt} (random)"

# Generate a hash using the C implementation
# shellcheck disable=SC3037 # POSIX sh, echo -n flag is not supported but ash in Alpine does
hashClang=$(echo -n "password" | argon2 "${salt}" -t 1 -m 16 -p 2 -l 32 -id | grep Encoded | sed -r 's/Encoded:(.)/\2/')
echo "Hash (Clang ): ${hashClang}"

# Generate a hash using the Golang implementation
hashGolang=$(sample "password" "${salt}")
echo "Hash (Golang): ${hashGolang}"

# Compare the two hashes
# It will exit as 0 if they are the same. Otherwise, it will exit as 1.
if [ "$hashClang" = "$hashGolang" ]; then
    echo "The hashes are the same."
    exit 0
else
    echo "The hashes are different."
    exit 1
fi
