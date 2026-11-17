<script setup lang="ts">
interface Props {
  name: string;
  size?: number;
  filled?: boolean;
  weight?: number;
}

withDefaults(defineProps<Props>(), {
  size: 20,
  filled: false,
  weight: 400,
});
</script>

<template>
  <span
    class="m3-symbol"
    aria-hidden="true"
    :style="{
      fontSize: `${size}px`,
      width: `${size}px`,
      height: `${size}px`,
      '--icon-fill': filled ? 1 : 0,
      '--icon-wght': weight,
    }"
  >
    {{ name }}
  </span>
</template>
