SECTIONS
{
	.text :
	{
		*( .text$A )
		*( .text$B )
		*( .text$C )
		*( .text$D )
		*( .text$E )
		*( .text$F )
		*( .rdata* )
		*( .text$G )
		*( .text$H )
		*( .text$I )
	}
}
