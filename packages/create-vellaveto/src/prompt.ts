import * as p from "@clack/prompts";

/**
 * Unwrap a @clack/prompts result, exiting if the user cancelled.
 *
 * The parameter is `T` rather than `T | symbol` on purpose. Clack returns
 * `T | typeof CANCEL_SYMBOL`, and against a `T | symbol` parameter TypeScript
 * is free to infer `T` as that whole union — so the cancel symbol survives
 * into the return type and every caller then sees `string | unique symbol`.
 * Taking `T` and returning `Exclude<T, symbol>` makes the inference carry the
 * union in and the narrowing strip the symbol out, which is what the
 * `isCancel` check below actually guarantees at runtime.
 */
export function requirePromptValue<T>(
  value: T,
  message = "Setup cancelled.",
): Exclude<T, symbol> {
  if (p.isCancel(value)) {
    p.cancel(message);
    process.exit(0);
  }

  return value as Exclude<T, symbol>;
}
