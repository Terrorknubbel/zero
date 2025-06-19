<template>
  <div class="app-container">
    <ContactList
      :contacts="contacts"
      :active-id="activeId"
      @select="handleSelect"
    />

    <ChatWindow
      v-if="activeId"
      :contact="contacts.find(c => c.id === activeId)!"
      :messages="messages[activeId] || []"
      @send="handleSend"
    />

    <div v-else class="empty-state">
      <p>Select a conversation to start chatting.</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { storeToRefs }           from 'pinia'
import { useChat }               from './stores/chat'

import ContactList from './components/ContactList.vue'
import ChatWindow   from './components/ChatWindow.vue'

/* ───────────────────────── Pinia-Store ───────────────────────── */
const chat = useChat()
const { contacts, messages } = storeToRefs(chat)

/* ───────────────────────── UI-State ──────────────────────────── */
const activeId = ref<string | null>(null)

/* Erst beim App-Start die Kontaktliste holen */
onMounted(chat.loadContacts)

/* Immer wenn ein Kontakt aktiv wird ⇒ Verlauf aus Backend nachladen */
watch(activeId, async id => {
  console.log('[Vue] activeId changed →', id)
  if (id) {
    await chat.loadHistory(id)   // jedes Mal frisch holen
  }
})

function handleSelect(id: string) {
  activeId.value = id
}

/* Senden + anschließend Verlauf erneut laden, damit die neue Nachricht
   (und evtl. Empfangs-Echo) garantiert aus dem Backend kommt */
async function handleSend(text: string) {
  const id = activeId.value
  if (!id) return

  try {
    await chat.send(id, text)    // legt Datei & Session an
    await chat.loadHistory(id)   // direkt danach refreshen
  } catch (e) {
    console.error('Send failed', e)
  }
}
</script>

<style scoped>
.app-container {
  display: flex;
  height: 100vh;
  background: #1e1e1e;
  color: #e4e4e4;
  font-family: "Inter", sans-serif;
}
.empty-state {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0.6;
}
</style>

