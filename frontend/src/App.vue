<template>
  <div class="app-container">
    <ContactList
      :contacts="contactPreviews"
      :active-id="activeContact?.id ?? null"
      @select="handleSelect"
    />

    <ChatWindow
      v-if="activeContact"
      :contact="activeContact"
      :messages="messages[activeContact.id] || []"
      @send="handleSend"
    />

    <div v-else class="empty-state">
      <p>Select a conversation to start chatting.</p>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, computed } from 'vue'
import ContactList from './components/ContactList.vue'
import ChatWindow   from './components/ChatWindow.vue'
import { SendMessage } from '../wailsjs/go/main/App'
import type { Contact } from './types'

interface Message { id: string; contactId: string; text: string; mine: boolean; timestamp: Date }

// --- Demo‑Daten (platzhalter) ---
const contacts = ref<Contact[]>([
  { id: '1', name: 'Alice', unread: 2 },
  { id: '2', name: 'Bob' },
])

const activeId = ref<string | null>(null)
const messages = reactive<Record<string, Message[]>>({
  '1': [
    { id: 'm1', contactId: '1', text: 'Hi there! 👋', mine: false, timestamp: new Date() },
  ],
})

const contactPreviews = computed<Contact[]>(() => {
  return contacts.value.map(c => {
    const conv    = messages[c.id] ?? []
    const lastMsg = conv.length ? conv[conv.length - 1].text : ''
    return { ...c, last: lastMsg }
  })
})

const activeContact = computed<Contact | null>(() =>
  contactPreviews.value.find(c => c.id === activeId.value) || null
)

function handleSelect(id: string) {
  activeId.value = id
}

async function handleSend(text: string) {
  if (!activeContact.value) return

  const contactId = activeContact.value.id
  const msg: Message = {
    id: crypto.randomUUID(),
    contactId,
    text,
    mine: true,
    timestamp: new Date(),
  }

  ;(messages[contactId] ||= []).push(msg) // optimistic update
  await SendMessage(text)                 // Wails‑Backend‑Call
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
