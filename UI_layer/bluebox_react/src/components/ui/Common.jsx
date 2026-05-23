import React from 'react'
import { X } from 'lucide-react'

export const MetricCard = ({ label, value, sublabel, variant = 'default', className = '' }) => {
  const variants = {
    default: 'border-bluebox-cyan',
    danger: 'border-bluebox-red',
    warning: 'border-bluebox-yellow',
    success: 'border-bluebox-green',
  }

  return (
    <div className={`card-panel ${variants[variant]} ${className}`}>
      <p className="text-eyebrow">{label}</p>
      <p className="text-3xl font-black text-bluebox-cyan">{value}</p>
      <p className="text-xs text-bluebox-muted">{sublabel}</p>
    </div>
  )
}

export const StatusPill = ({ status, variant = 'neutral' }) => {
  const variants = {
    verified: 'status-pill verified',
    failed: 'status-pill failed',
    pending: 'status-pill',
    neutral: 'status-pill',
  }

  return (
    <span className={variants[variant]}>
      {status}
    </span>
  )
}

export const Panel = ({ title, subtitle, children, className = '', headerAction = null }) => {
  return (
    <div className={`card-panel flex flex-col gap-4 ${className}`}>
      <div className="flex justify-between items-start">
        <div>
          <p className="text-eyebrow">{title}</p>
          <h3 className="text-heading-2">{subtitle}</h3>
        </div>
        {headerAction && <div>{headerAction}</div>}
      </div>
      {children}
    </div>
  )
}

export const Button = ({ children, variant = 'primary', disabled = false, onClick, className = '', ...props }) => {
  const variants = {
    primary: 'btn-primary',
    ghost: 'btn-ghost',
    success: 'btn-success',
    danger: 'btn-danger',
    warning: 'btn-warning',
  }

  return (
    <button
      className={`${variants[variant]} ${className}`}
      disabled={disabled}
      onClick={onClick}
      {...props}
    >
      {children}
    </button>
  )
}

export const Input = ({ label, value, onChange, type = 'text', placeholder = '', className = '', ...props }) => {
  return (
    <div className="flex flex-col gap-2">
      {label && <label className="text-sm font-semibold text-bluebox-text">{label}</label>}
      <input
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className={`input-field ${className}`}
        {...props}
      />
    </div>
  )
}

export const Textarea = ({ label, value, onChange, placeholder = '', className = '', rows = 4, ...props }) => {
  return (
    <div className="flex flex-col gap-2">
      {label && <label className="text-sm font-semibold text-bluebox-text">{label}</label>}
      <textarea
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        rows={rows}
        className={`input-field resize-none ${className}`}
        {...props}
      />
    </div>
  )
}

export const Select = ({ label, value, onChange, options = [], className = '' }) => {
  return (
    <div className="flex flex-col gap-2">
      {label && <label className="text-sm font-semibold text-bluebox-text">{label}</label>}
      <select
        value={value}
        onChange={onChange}
        className={`input-field ${className}`}
      >
        {options.map(opt => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  )
}

export const Alert = ({ children, variant = 'info', className = '' }) => {
  const variants = {
    info: 'alert-card',
    warning: 'alert-card warning',
    critical: 'alert-card critical',
  }

  return (
    <div className={`${variants[variant]} ${className}`}>
      {children}
    </div>
  )
}

const spinnerSizes = {
  sm: 'w-4 h-4 border-2',
  md: 'w-6 h-6 border-2',
  lg: 'w-10 h-10 border-4',
}

export const Spinner = ({ size = 'md', className = '' }) => (
  <span className={`inline-flex items-center justify-center ${className}`} role="status" aria-label="Loading">
    <span
      className={`${spinnerSizes[size] || spinnerSizes.md} block animate-spin rounded-full border-bluebox-cyan border-t-bluebox-aqua`}
    />
  </span>
)

export const LoadingSpinner = () => (
  <div className="flex items-center justify-center py-8">
    <Spinner size="lg" />
  </div>
)

export const Toast = ({ message, show = false, className = '' }) => {
  return (
    <div className={`fixed bottom-4 right-4 px-4 py-3 rounded-lg bg-bluebox-panel border border-bluebox-cyan transition-smooth ${show ? 'opacity-100' : 'opacity-0 pointer-events-none'} ${className}`}>
      {message}
    </div>
  )
}

export const Table = ({ columns, rows = [], onRowClick = null }) => {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-cyan-900">
            {columns.map(col => (
              <th key={col.key} className="text-left py-2 px-3 font-semibold text-bluebox-muted">
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, idx) => (
            <tr
              key={idx}
              className={`border-b border-cyan-900 transition-smooth ${onRowClick ? 'hover:bg-cyan-900 hover:bg-opacity-20 cursor-pointer' : ''}`}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map(col => (
                <td key={col.key} className="py-2 px-3">
                  {col.render ? col.render(row[col.key], row) : row[col.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export const Modal = ({ title, children, isOpen = false, onClose = null, actions = null }) => {
  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="card-panel w-96 max-h-96 overflow-y-auto flex flex-col gap-4">
        <div className="flex justify-between items-center">
          <h2 className="text-heading-2">{title}</h2>
          <button onClick={onClose} className="text-bluebox-muted hover:text-bluebox-text">
            <X size={18} aria-label="Close" />
          </button>
        </div>
        <div>{children}</div>
        {actions && <div className="flex gap-2 justify-end">{actions}</div>}
      </div>
    </div>
  )
}
