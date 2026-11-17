import { createRouter, createWebHistory } from "vue-router";
import { getRuntimeConfig } from "@/lib/bootstrap";
import { useAppStore } from "@/stores/app";

const router = createRouter({
  history: createWebHistory(getRuntimeConfig().appBasePath),
  routes: [
    {
      path: "/login",
      name: "login",
      component: () => import("@/views/LoginView.vue"),
      meta: { requiresGuest: true },
    },
    {
      path: "/",
      name: "overview",
      component: () => import("@/views/OverviewView.vue"),
      meta: { requiresAuth: true },
    },
    {
      path: "/cores",
      name: "cores",
      component: () => import("@/views/CoresView.vue"),
      meta: { requiresAuth: true, requiresCorePerm: true },
    },
    {
      path: "/:pathMatch(.*)*",
      name: "not-found",
      component: () => import("@/views/NotFoundView.vue"),
    },
  ],
});

router.beforeEach(async (to) => {
  const appStore = useAppStore();
  if (!appStore.initialized) {
    await appStore.initBootstrap().catch(() => undefined);
  }

  if (to.meta.requiresAuth && !appStore.authenticated) {
    return { name: "login" };
  }
  if (to.meta.requiresGuest && appStore.authenticated) {
    return { name: "overview" };
  }
  if (
    to.meta.requiresCorePerm &&
    !(appStore.perms.coreSettings || appStore.user?.isSuperAdmin)
  ) {
    return { name: "overview" };
  }
  return true;
});

export default router;
