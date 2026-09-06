"""Invite codes: three words from this list plus two digits, e.g. coral-lounger-palm-42.
256^3 * 100 is about 2^30; with ten tries per five minutes per IP that is out of reach for an invite that lives days."""
from __future__ import annotations

import secrets

WORDS = (
    "coral", "lounger", "palm", "tide", "reef", "lagoon", "sand", "dune", "shell", "pearl", "wave", "foam", "surf", "swell", "breeze", "gust",
    "cloud", "storm", "sun", "moon", "star", "dusk", "dawn", "noon", "night", "shade", "lantern", "torch", "candle", "ember", "spark", "flame",
    "driftwood", "plank", "deck", "dock", "pier", "jetty", "harbor", "anchor", "buoy", "sail", "mast", "rope", "knot", "net", "hook", "boat",
    "canoe", "kayak", "paddle", "oar", "raft", "yacht", "ferry", "skiff", "dinghy", "compass", "chart", "map", "atlas", "globe", "island", "cove",
    "bay", "inlet", "cape", "bluff", "cliff", "ridge", "peak", "summit", "valley", "meadow", "grove", "orchard", "garden", "vine", "fern", "moss",
    "cactus", "agave", "aloe", "mango", "papaya", "guava", "lime", "lemon", "coconut", "banana", "pineapple", "melon", "berry", "cherry", "plum", "peach",
    "apricot", "fig", "olive", "date", "almond", "cashew", "pecan", "walnut", "hazel", "maple", "cedar", "pine", "spruce", "willow", "birch", "oak",
    "elm", "ash", "aspen", "poplar", "bamboo", "rattan", "wicker", "linen", "cotton", "silk", "wool", "denim", "canvas", "burlap", "velvet", "satin",
    "amber", "jade", "opal", "onyx", "ruby", "topaz", "garnet", "quartz", "agate", "marble", "granite", "slate", "flint", "basalt", "pumice", "sandal",
    "towel", "hammock", "parasol", "umbrella", "cabana", "bungalow", "villa", "lodge", "cabin", "tent", "hut", "kiosk", "pavilion", "terrace", "veranda", "balcony",
    "patio", "porch", "gazebo", "pergola", "trellis", "fountain", "pond", "spring", "creek", "brook", "river", "delta", "marsh", "bayou", "fjord", "glacier",
    "iceberg", "tundra", "desert", "oasis", "mirage", "canyon", "mesa", "butte", "plateau", "prairie", "savanna", "jungle", "forest", "thicket", "hedge", "lawn",
    "clover", "daisy", "tulip", "lily", "rose", "iris", "poppy", "lotus", "orchid", "jasmine", "lilac", "lavender", "sage", "thyme", "basil", "mint",
    "dill", "fennel", "ginger", "pepper", "nutmeg", "clove", "vanilla", "cocoa", "coffee", "tea", "sugar", "honey", "syrup", "butter", "cream", "milk",
    "bread", "toast", "bagel", "muffin", "waffle", "pancake", "omelet", "pretzel", "cracker", "pickle", "mustard", "salsa", "taco", "kettle", "teapot", "mug",
    "cup", "bowl", "plate", "spoon", "fork", "ladle", "basket", "bucket", "barrel", "crate", "trunk", "drawer", "shelf", "ladder", "wagon", "bicycle",
)


def new_code(rand=secrets) -> str:
    picks = [WORDS[rand.randbelow(len(WORDS))] for _ in range(3)]
    return f"{picks[0]}-{picks[1]}-{picks[2]}-{rand.randbelow(100):02d}"


def normalize(code: str) -> str:
    """What a person typed -> the stored form: lowercase, single hyphens, no stray spaces."""
    parts = (code or "").strip().lower().replace(" ", "-").split("-")
    return "-".join(p for p in parts if p)
