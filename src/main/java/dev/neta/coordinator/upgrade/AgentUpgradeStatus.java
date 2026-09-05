package dev.neta.coordinator.upgrade;

import java.util.EnumSet;

public enum AgentUpgradeStatus {
    REQUESTED,
    DELIVERED,
    DOWNLOADING,
    INSTALLING,
    LOCAL_HEALTHY,
    CONFIRMED,
    FAILED,
    ROLLED_BACK;

    private static final EnumSet<AgentUpgradeStatus> TERMINAL = EnumSet.of(CONFIRMED, FAILED, ROLLED_BACK);

    public boolean terminal() {
        return TERMINAL.contains(this);
    }
}
