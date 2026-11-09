import { invoke } from "@tauri-apps/api/core";
import { disable, enable, isEnabled } from "@tauri-apps/plugin-autostart";
import { Show, createSignal, onMount } from "solid-js";

import { Icon } from "./icons.tsx";

/** The settings button and its menu: Settings, Launch at login and Quit. */
export function Menu(props: { onSettings: () => void; onError: (error: string) => void }) {
  const [login, setLogin] = createSignal(false);
  const [menu, setMenu] = createSignal(false);
  onMount(() => {
    isEnabled()
      .then(setLogin)
      .catch(() => setLogin(false));
  });
  const toggleLogin = (event: Event & { currentTarget: HTMLInputElement }) => {
    const box = event.currentTarget;
    (login() ? disable() : enable())
      .catch((e: unknown) => props.onError(String(e)))
      .finally(() => {
        // The box shows what is set, even when changing it failed.
        isEnabled()
          .then((on) => {
            setLogin(on);
            box.checked = on;
          })
          .catch(() => undefined);
      });
  };
  return (
    <div class="menu-wrap">
      <button
        type="button"
        class="ghost"
        aria-label="Settings"
        title="Settings"
        aria-expanded={menu()}
        onClick={() => setMenu(!menu())}
      >
        <Icon name="settings" />
      </button>
      <Show when={menu()}>
        <div class="menu" role="menu">
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setMenu(false);
              props.onSettings();
            }}
          >
            Settings…
          </button>
          <label class="menuitem">
            <input id="login" type="checkbox" checked={login()} onChange={toggleLogin} />
            Launch at login
          </label>
          <hr />
          <button type="button" role="menuitem" onClick={() => void invoke("quit")}>
            Quit Vigil
          </button>
        </div>
      </Show>
    </div>
  );
}
