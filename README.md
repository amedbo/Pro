# Academic Cyber Range Platform

This project is an advanced cybersecurity training platform designed for both beginners and professionals. It provides a simulated environment (Cyber Range) for users to practice and learn offensive (Red Team) and defensive (Blue Team) security techniques in a safe, controlled setting.

## Project Vision

The goal is to build a modular and extensible platform that can:
- Host realistic network scenarios involving various operating systems and hardware (virtualized).
- Provide tools for both attacking and defending teams.
- Offer an "academic" focus through detailed logging, performance metrics, and automated reporting.
- Support advanced scenarios like vulnerability research, mobile hacking, and bypassing modern defenses.

## Getting Started

### 1. Prerequisites

Before running the platform, you need a Linux machine with KVM and libvirt installed. You will also need the following command-line tools:
- `wget`
- `qemu-utils` (provides `qemu-img`)
- `libguestfs-tools` (provides `virt-customize`)

On a Debian/Ubuntu system, you can install these with:
```bash
sudo apt-get update
sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils qemu-utils libguestfs-tools
```

### 2. Image Preparation

The virtual machine images used in the scenarios are not stored in this repository due to their large size. Instead, a helper script is provided to build them automatically.

To build the necessary images, run the following command from the root of the project:
```bash
bash scripts/build_images.sh
```
This script will download the official base images for Ubuntu and VyOS and then use them to create the customized images needed for the scenarios. The final images will be placed in the `base_images/` directory.

## Technology Stack

- **Virtualization:** KVM/QEMU managed via `libvirt`. Chosen for its power and flexibility in running full virtual machines for various OSes.
- **Backend:** Python/Flask. A lightweight and powerful choice for the API server, with excellent support for `libvirt`.
- **Frontend:** React.js. A modern and popular framework for building the interactive user dashboard.
- **Orchestration:** Custom Python scripts using the `libvirt-python` library. This provides direct, fine-grained control over the virtualized resources.
