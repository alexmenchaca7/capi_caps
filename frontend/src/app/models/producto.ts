export class Producto{
    constructor(
        public id:number,
        public nombre: string,
        public cantidad?: number, 
        public precio?: number, 
        public imagen:string = ''
    ){}
}   