package com.cymylive.totpgen

data class Account(
    val name: String,
    val secret: String,
    val digits: Int = 6,
    val period: Int = 30
)
