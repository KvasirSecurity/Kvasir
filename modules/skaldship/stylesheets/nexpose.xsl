<xsl:stylesheet version="1.0"
     xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output encoding="UTF-8" indent="yes"/>

<!--<xsl:template match="description">
    <xsl:apply-templates/>
</xsl:template>

<xsl:template match="solution">
    <xsl:apply-templates/>
</xsl:template>-->

<xsl:template match="ContainerBlockElement">
    <xsl:apply-templates select="Paragraph"/>
    <xsl:apply-templates select="Table"/>
    <xsl:apply-templates select="URLLink"/>
    <xsl:apply-templates select="OrderedList"/>
    <xsl:apply-templates select="UnorderedList"/>
    <xsl:apply-templates select="ListItem"/>
</xsl:template>

<xsl:template match="Paragraph">
    <xsl:choose>
        <xsl:when test="@preformat">
            <pre>
                <xsl:apply-templates/>
            </pre>
        </xsl:when>
        <xsl:otherwise>
            <p>
                <xsl:apply-templates/>
            </p>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<xsl:template match='Table'>
    <table title="{@TableTitle}" border="1">
        <xsl:for-each select="TableHeader">
            <TH>
                <xsl:value-of select="text()"/>
                <xsl:apply-templates/>
            </TH>
        </xsl:for-each>
        <xsl:for-each select="TableRow">
            <TR title="{@RowTitle}">
                <xsl:for-each select="TableCell">
                    <TD>
                    <xsl:apply-templates/>
                    </TD>
                </xsl:for-each>
            </TR>
        </xsl:for-each>
    </table>
</xsl:template>

<xsl:template match="URLLink">
    <a href="{@LinkURL}" target="_blank">
        <xsl:value-of select="text()"/>
    </a>
</xsl:template>

<xsl:template match="OrderedList">
    <ol>
        <xsl:apply-templates/>
    </ol>
</xsl:template>

<xsl:template match="UnorderedList">
    <ul>
        <xsl:apply-templates/>
    </ul>
</xsl:template>

<xsl:template match="ListItem">
    <li>
        <xsl:apply-templates/>
    </li>
</xsl:template>

<xsl:template match="*">
    <p>
        <xsl:apply-templates/>
    </p>
</xsl:template>

</xsl:stylesheet>
