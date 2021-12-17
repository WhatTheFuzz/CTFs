FROM ubuntu:latest as base

COPY ./chall.S /chall.S

# Install the items necessary to run it.
RUN apt-get update && apt-get install -y \
    binutils-aarch64-linux-gnu \
    qemu-user-static \
    gcc-aarch64-linux-gnu

# Compile the challenge.
RUN aarch64-linux-gnu-gcc -static chall.S -o chall

# Run the challenge.
RUN ./chall 182476535 3742084308 | echo