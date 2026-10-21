import React from 'react'
import ReactDOM from 'react-dom/client'
import '@ant-design/v5-patch-for-react-19'
import { ConfigProvider, App as AntApp } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import App from './App'
import '@xyflow/react/dist/style.css'
import './styles.css'
import './business.css'
import './console.css'
import './studio.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: '#255bde',
          colorInfo: '#255bde',
          colorSuccess: '#137758',
          colorWarning: '#936616',
          colorError: '#b33741',
          colorSuccessBg: '#eaf6f0',
          colorSuccessBorder: '#cfe8dd',
          colorInfoBg: '#edf3ff',
          colorInfoBorder: '#cbdaf8',
          colorWarningBg: '#fbf5e9',
          colorWarningBorder: '#ecdfc4',
          colorErrorBg: '#fff0f1',
          colorErrorBorder: '#f0cfd3',
          colorText: '#18232e',
          colorTextSecondary: '#596775',
          colorTextTertiary: '#596775',
          colorBorder: '#e5ebf1',
          colorBorderSecondary: '#e5ebf1',
          colorFillAlter: '#f8fafc',
          colorBgLayout: '#ffffff',
          controlHeight: 40,
          fontSize: 16,
          fontSizeSM: 14,
          borderRadius: 6,
          fontFamily: 'Inter, "Segoe UI", "Microsoft YaHei", sans-serif',
        },
      }}
    >
      <AntApp>
        <App />
      </AntApp>
    </ConfigProvider>
  </React.StrictMode>,
)
