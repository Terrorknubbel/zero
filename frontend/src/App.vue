<!-- src/App.vue -->
<script lang="ts" setup>
import { ref } from 'vue'
import {SendMessage} from '../wailsjs/go/main/App'

const input   = ref('')

function handleSend() {
  if(!input.value.trim()) return
  SendMessage(input.value).then(() => input.value = '')
}
</script>

<template>
  <form @submit.prevent="handleSend" style="text-align:center; margin-top:2rem;">
    <input v-model="input"
           placeholder="Type a message ..."
           style="width:70%; padding:0.5rem;" />

    <button style="padding:0.55rem 1rem; margin-left:0.5rem;">
      Send
    </button>
  </form>
</template>
