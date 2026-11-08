import { useCallback, useRef, useState } from "react";

/**
 * An uncontrolled password field (L-53, the SecurityCard / SmartCardPinDialog pattern). The value
 * lives only in the DOM input: React state holds whether it is empty, never the text. `take()`
 * reads it once and empties the field. The field is also emptied when it leaves the page (the
 * dialog closes or the step changes), through the callback ref's detach call.
 */
export function useSecretInput() {
  const node = useRef<HTMLInputElement | null>(null);
  const [empty, setEmpty] = useState(true);

  // Stable on purpose: a new callback each render would detach and empty the field every time.
  const ref = useCallback((el: HTMLInputElement | null) => {
    if (el) {
      node.current = el;
      return;
    }
    if (node.current) node.current.value = "";
    node.current = null;
  }, []);

  const onChange = useCallback((e: { target: { value: string } }) => { setEmpty(e.target.value === ""); }, []);
  /** The current text, left in the field (for checks before sending). */
  const peek = useCallback(() => node.current?.value ?? "", []);
  const clear = useCallback(() => {
    if (node.current) node.current.value = "";
    setEmpty(true);
  }, []);
  /** Reads the text once and empties the field. */
  const take = useCallback(() => {
    const v = node.current?.value ?? "";
    clear();
    return v;
  }, [clear]);

  return { ref, empty, onChange, peek, take, clear };
}
