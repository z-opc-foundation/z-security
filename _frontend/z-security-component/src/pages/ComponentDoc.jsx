import {ComponentDoc} from '@yuku123/z-frontend-common/ui'
import docMarkdown from '../DOC.md?raw'

/** 组件文档页（lead 008 §7）—— 文档内容来自本包 src/DOC.md（?raw 内联，随包发布）。 */
export default function ComponentDocPage() {
    return <ComponentDoc markdown={docMarkdown} title="组件文档 — security" />
}
