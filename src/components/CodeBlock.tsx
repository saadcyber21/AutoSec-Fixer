import { useState } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface CodeBlockProps {
  code: string;
  language: string;
  filename?: string;
  maxHeight?: string;
}

export default function CodeBlock({ code, language, filename, maxHeight = '600px' }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-xl overflow-hidden border border-gray-700/50 shadow-2xl my-4">
      {filename && (
        <div className="flex items-center justify-between bg-gray-800 px-4 py-2.5 border-b border-gray-700/50">
          <div className="flex items-center gap-2">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
              <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
            </div>
            <span className="text-sm text-gray-400 font-mono ml-2">{filename}</span>
          </div>
          <button
            onClick={handleCopy}
            className="text-xs px-3 py-1 rounded-md bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
          >
            {copied ? '✓ Copied' : 'Copy'}
          </button>
        </div>
      )}
      <div style={{ maxHeight }} className="overflow-auto">
        <SyntaxHighlighter
          language={language}
          style={oneDark}
          customStyle={{
            margin: 0,
            padding: '1.25rem',
            fontSize: '0.8rem',
            lineHeight: '1.6',
            background: '#1a1b26',
          }}
          showLineNumbers={true}
          lineNumberStyle={{ color: '#4a5568', fontSize: '0.7rem' }}
        >
          {code}
        </SyntaxHighlighter>
      </div>
    </div>
  );
}
