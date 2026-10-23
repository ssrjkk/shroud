/**
 * Role guides: what each side does, in the bot and outside it.
 *
 * Static text, no chain reads — a newcomer tapping a role button gets the one
 * screen that tells them what to do next, in their language. Bodies live in
 * the i18n dictionary (single source); this module owns the role list and
 * the lookup.
 */
import { t } from "./i18n.js";

export const ROLES = ["buyer", "contrib", "node", "watch"];
/**
 * What a user may type after /role. Short forms work too: the buttons send
 * `r:contrib` / `r:watch` and RU aliases normalize to the same roots, so
 * rejecting them here stranded both paths on the role picker.
 */
export const ROLE_ALIASES = {
  buyer: "buyer",
  contributor: "contrib",
  contrib: "contrib",
  node: "node",
  watcher: "watch",
  watch: "watch",
};
const ROLE_KEYS_GEEK = { buyer: "role.buyerB", contrib: "role.contribB", node: "role.nodeB", watch: "role.watchB" };
const ROLE_KEYS_SIMPLE = { buyer: "role.buyerS", contrib: "role.contribS", node: "role.nodeS", watch: "role.watchS" };

export function isRole(v) {
  return ROLES.includes(v);
}

/**
 * Full guide for a role, or null for an unknown key.
 *
 * Mode-aware: `simple` gets 3 plain steps, anything else gets the geek
 * version (contracts, SDK, crypto). Defaults to geek so old callers
 * without a mode keep the historical text byte-identical.
 */
export function renderRole(role, lang, mode = "pro") {
  if (!isRole(role)) return null;
  if (mode === "simple") return t(lang, ROLE_KEYS_SIMPLE[role]);
  return t(lang, ROLE_KEYS_GEEK[role]);
}
