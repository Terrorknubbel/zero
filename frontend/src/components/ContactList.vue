<template>
  <div class="sidebar">
    <div
      v-for="c in contacts"
      :key="c.id"
      :class="['contact', { active: c.id === activeId } ]"
      @click="$emit('select', c.id)"
    >
      <div class="avatar">{{ c.name.charAt(0).toUpperCase() }}</div>
      <div class="info">
        <div class="meta">
          <span>{{ c.name }}</span>
          <span v-if="c.last" class="last">{{ c.last }}</span>
        </div>

        <span v-if="c.unread" class="badge">{{ c.unread }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { Contact } from '../types'

defineProps<{ contacts: Contact[]; activeId: string | null }>()
</script>

<style scoped>
.sidebar {
  width: 260px;
  background: #2b2b2b;
  border-right: 1px solid #333;
  overflow-y: auto;
}
.contact {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  cursor: pointer;
  transition: background 0.2s;
}
.contact:hover { background: #373737; }
.contact.active { background: #444; }
.avatar {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: #555;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
}
.info {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex: 1;
}
.meta {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  flex: 1;
}
.last {
  font-size: 0.8rem;
  opacity: 0.7;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  word-break: break-word;
}
</style>
