"""Spec-layout name for the wrap boundary.

The implementation lives in `toolwarden.boundary`; this module exists so
that the layout in the spec (and `Gate.wrap`'s lazy import of
`toolwarden.wrap`) resolves to the same single implementation. Nothing may
be defined here: two definitions of the guard would be two behaviors for
one contract.
"""

from toolwarden.boundary import wrap_tools

__all__ = ("wrap_tools",)
