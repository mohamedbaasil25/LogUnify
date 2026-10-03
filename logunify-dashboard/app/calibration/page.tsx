"use client";

import CalibrationView from "@/components/CalibrationView";
import RoleGate from "@/components/RoleGate";

export default function CalibrationPage() {
  return (
    <RoleGate min="analyst" what="Alert calibration">
      <CalibrationView />
    </RoleGate>
  );
}
