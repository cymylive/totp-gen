package com.cymylive.totpgen

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class AccountAdapter(
    private val items: MutableList<Account>,
    private val onClick: (Int) -> Unit,
    private val onLongClick: (Int) -> Unit
) : RecyclerView.Adapter<AccountAdapter.VH>() {

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val name: TextView = v.findViewById(R.id.tvName)
        val code: TextView = v.findViewById(R.id.tvCode)
        val remain: TextView = v.findViewById(R.id.tvRemain)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_account, parent, false)
        return VH(v)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: VH, position: Int) {
        val acc = items[position]
        holder.name.text = acc.name
        holder.itemView.setOnClickListener { onClick(position) }
        holder.itemView.setOnLongClickListener {
            onLongClick(position)
            true
        }
        refresh(holder, position)
    }

    fun refresh(holder: VH, position: Int) {
        if (position !in items.indices) return
        val acc = items[position]
        val code = try {
            Totp.totp(acc.secret, period = acc.period, digits = acc.digits)
        } catch (e: Exception) {
            "ERROR"
        }
        holder.code.text = code
        val remain = Totp.remainingSeconds(acc.period)
        holder.remain.text = "${remain}s"
        holder.remain.alpha = if (remain <= 5) 0.45f else 1f
    }

    fun refreshAll() {
        for (i in 0 until itemCount) notifyItemChanged(i, PAYLOAD_TICK)
    }

    fun submit(newItems: List<Account>) {
        items.clear()
        items.addAll(newItems)
        notifyDataSetChanged()
    }

    companion object {
        const val PAYLOAD_TICK = "tick"
    }
}
