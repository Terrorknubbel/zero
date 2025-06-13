<template>
  <div class="chat-window">
    <header class="chat-header">
      <div class="avatar">{{ contact.name.charAt(0).toUpperCase() }}</div>
      <h2>{{ contact.name }}</h2>
    </header>

    <main class="messages" ref="scrollContainer">
      <div
        v-for="m in messages"
        :key="m.id"
        :class="['message', m.mine ? 'mine' : 'theirs']"
      >
        <span>{{ m.text }}</span>
        <span class="timestamp">{{ new Date(m.timestamp).toLocaleTimeString() }}</span>
      </div>
    </main>

    <footer class="input-area">
      <form @submit.prevent="send">
        <input v-model="draft" placeholder="Type a message…" />
        <button>
          <span>Send</span>
        </button>
      </form>
    </footer>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'

interface Contact  { id: string; name: string }
interface Message  { id: string; contactId: string; text: string; mine: boolean; timestamp: Date }

const props = defineProps<{ contact: Contact; messages: Message[] }>()
const emit  = defineEmits<{ (e: 'send', text: string): void }>()

const draft = ref('')
const scrollContainer = ref<HTMLElement | null>(null)

function send() {
  if (!draft.value.trim()) return
  emit('send', draft.value)
  draft.value = ''
}

watch(() => props.messages.length, async () => {
  await nextTick()
  scrollContainer.value?.scrollTo({ top: scrollContainer.value.scrollHeight })
})
</script>

<style scoped>
.chat-window {
  flex: 1;
  display: flex;
  flex-direction: column;
  height: 100%;
}
.chat-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0 1rem;
  background: #2b2b2b;
  border-bottom: 1px solid #333;
}
.chat-header .avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: #555;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
}
.messages {
  flex: 1;
  overflow-y: auto;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.message {
  max-width: 60%;
  padding: 0.6rem 0.8rem;
  border-radius: 0.75rem;
  font-size: 0.95rem;
  white-space: pre-wrap;     /* respect newlines */
  overflow-wrap: anywhere;   /* break long words/URLs */
  word-break: break-word;
  text-align: left;
}
.message.mine {
  align-self: flex-end;
  background: #3d6be6;
  color: white;
  border-bottom-right-radius: 0;
}
.message.theirs {
  align-self: flex-start;
  background: #333;
  color: #e4e4e4;
  border-bottom-left-radius: 0;
}
.timestamp {
  display: block;
  font-size: 0.7rem;
  opacity: 0.6;
  margin-top: 0.25rem;
  text-align: right;
}
.input-area {
  border-top: 1px solid #333;
  padding: 0.5rem 0.75rem;
}
.input-area form {
  display: flex;
  gap: 0.5rem;
}
.input-area input {
  flex: 1;
  padding: 0.55rem 0.75rem;
  border-radius: 0.5rem;
  border: none;
  background: #262626;
  color: white;
}
.input-area button {
  padding: 0 1rem;
  border: none;
  background: #3d6be6;
  color: white;
  border-radius: 0.5rem;
  cursor: pointer;
}
</style>
