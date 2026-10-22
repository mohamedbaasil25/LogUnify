"use client";

import RoleGate from "@/components/RoleGate";
import SearchView from "@/components/SearchView";

export default function SearchPage() {
  return (
    <RoleGate min="analyst" what="Log search and saved searches">
      <SearchView />
    </RoleGate>
  );
}
