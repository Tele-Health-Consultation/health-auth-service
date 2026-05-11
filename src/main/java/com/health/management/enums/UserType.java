package com.health.management.enums;

public enum UserType {

    PATIENT("PATIENT"),
    DOCTOR("DOCTOR"),
    CLINIC("CLINIC");

    private String value;

    UserType(String value) {
        this.value = value;
    }
}
