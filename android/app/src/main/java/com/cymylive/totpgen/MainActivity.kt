package com.cymylive.totpgen

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.cymylive.totpgen.databinding.ActivityMainBinding
import com.cymylive.totpgen.databinding.DialogAddBinding
import com.google.android.material.dialog.MaterialAlertDialogBuilder

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var store: SecureStore
    private lateinit var adapter: AccountAdapter
    private val accounts = mutableListOf<Account>()

    private val handler = Handler(Looper.getMainLooper())
    private val tickRunnable = object : Runnable {
        override fun run() {
            adapter.refreshAll()
            binding.progress.progress = Totp.remainingSeconds()
            handler.postDelayed(this, 500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        store = SecureStore(this)
        accounts.addAll(store.load())

        adapter = AccountAdapter(
            items = accounts,
            onClick = { pos -> copyCode(pos) },
            onLongClick = { pos -> showActions(pos) }
        )
        binding.recycler.layoutManager = LinearLayoutManager(this)
        binding.recycler.adapter = adapter

        binding.toolbar.setOnMenuItemClickListener { item ->
            if (item.itemId == R.id.action_add) {
                showAddDialog()
                true
            } else false
        }

        binding.progress.max = 30
        updateEmptyState()
    }

    override fun onResume() {
        super.onResume()
        handler.post(tickRunnable)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(tickRunnable)
    }

    private fun updateEmptyState() {
        val empty = accounts.isEmpty()
        binding.emptyHint.visibility = if (empty) View.VISIBLE else View.GONE
        binding.recycler.visibility = if (empty) View.GONE else View.VISIBLE
    }

    private fun copyCode(pos: Int) {
        if (pos !in accounts.indices) return
        val acc = accounts[pos]
        val code = try {
            Totp.totp(acc.secret, period = acc.period, digits = acc.digits)
        } catch (e: Exception) {
            Toast.makeText(this, "生成失败：${e.message}", Toast.LENGTH_SHORT).show()
            return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("TOTP", code))
        Toast.makeText(this, getString(R.string.copied_toast, acc.name, code), Toast.LENGTH_SHORT).show()
    }

    private fun showActions(pos: Int) {
        if (pos !in accounts.indices) return
        val acc = accounts[pos]
        val options = arrayOf("编辑", "删除")
        MaterialAlertDialogBuilder(this)
            .setTitle(acc.name)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> showAddDialog(editIndex = pos)
                    1 -> confirmDelete(pos)
                }
            }
            .show()
    }

    private fun confirmDelete(pos: Int) {
        val acc = accounts[pos]
        MaterialAlertDialogBuilder(this)
            .setMessage(getString(R.string.confirm_delete, acc.name))
            .setNegativeButton(R.string.btn_cancel, null)
            .setPositiveButton(R.string.delete) { _, _ ->
                accounts.removeAt(pos)
                persist()
            }
            .show()
    }

    private fun showAddDialog(editIndex: Int? = null) {
        val db = DialogAddBinding.inflate(LayoutInflater.from(this))
        val editing = editIndex != null && editIndex in accounts.indices
        if (editing) {
            val a = accounts[editIndex!!]
            db.etName.setText(a.name)
            db.etSecret.setText(a.secret)
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(if (editing) R.string.dialog_edit_title else R.string.dialog_add_title)
            .setView(db.root)
            .setNegativeButton(R.string.btn_cancel, null)
            .setPositiveButton(R.string.btn_save) { _, _ ->
                val nameInput = db.etName.text?.toString()?.trim().orEmpty()
                val secretInput = db.etSecret.text?.toString()?.trim().orEmpty()
                saveAccount(editIndex, nameInput, secretInput)
            }
            .show()
    }

    private fun saveAccount(editIndex: Int?, nameInput: String, secretInput: String) {
        var name = nameInput
        var secret = secretInput
        var digits = 6
        var period = 30

        if (secret.lowercase().startsWith("otpauth://")) {
            val info = Totp.parseOtpAuth(secret)
            if (info == null) {
                toast(getString(R.string.err_bad_otpauth))
                return
            }
            if (name.isEmpty()) name = info.name
            secret = info.secret
            digits = info.digits
            period = info.period
        }

        if (name.isEmpty()) {
            toast(getString(R.string.err_empty_name)); return
        }
        if (secret.isEmpty()) {
            toast(getString(R.string.err_empty_secret)); return
        }
        try {
            Totp.base32Decode(secret)
        } catch (e: Exception) {
            toast(getString(R.string.err_bad_secret)); return
        }

        val newAcc = Account(name, secret, digits, period)

        if (editIndex != null && editIndex in accounts.indices) {
            accounts[editIndex] = newAcc
        } else {
            val dup = accounts.indexOfFirst { it.name == name }
            if (dup >= 0) {
                MaterialAlertDialogBuilder(this)
                    .setMessage(getString(R.string.confirm_overwrite, name))
                    .setNegativeButton(R.string.btn_cancel, null)
                    .setPositiveButton(R.string.btn_save) { _, _ ->
                        accounts[dup] = newAcc
                        persist()
                    }
                    .show()
                return
            }
            accounts.add(newAcc)
        }
        persist()
    }

    private fun persist() {
        try {
            store.save(accounts)
        } catch (e: Exception) {
            toast("保存失败：${e.message}")
            return
        }
        adapter.submit(accounts)
        updateEmptyState()
    }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }
}
