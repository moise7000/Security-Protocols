# Security Protocols and Verification Project

## Project Overview

This project focuses on the design and analysis of cryptographic protocols in three main phases:
1. **Protocol Design** - Design a secret exchange protocol
2. **Protocol Attacks** - Attack other teams' protocols and defend your own
3. **Formal Analysis** - Model and analyze protocols using Tamarin

## Objective

Design a protocol that allows two agents A and B to exchange a freshly generated secret. At the end of the protocol execution, both agents must share the same secret value while ensuring it remains confidential.

## Initial Assumptions

- Agents A and B know all public keys (including each other's)
- Both agents may share a symmetric key with an honest server S
- **No shared key K_AB exists initially between A and B**

## Security Requirements

The protocol must guarantee the following properties:

1. **Authentication**: If B finishes a protocol run believing he received key K from A, then A actually sent K to B
2. **Confirmation**: If A finishes a protocol run having sent K to B, then B has actually received K from A
3. **Secrecy**: The key K must remain secret between A and B (and potentially server S)
4. **Freshness**: Each session must exchange a new fresh key K

